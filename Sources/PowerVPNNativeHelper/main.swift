import Darwin
import Foundation
import PowerVPNCore

// Root LaunchDaemon for the native backend.
//
// It owns two things the user-level CLI cannot do itself:
//   1. keep the patched charon running, with its VICI socket kept root-only;
//   2. add one host route per tunnel into charon's virtual-IP utun, and take it
//      away again when asked or when the IKE SA behind it is gone.
// The control socket accepts status, route-add, route-delete, log-tail and
// restart-charon only, from the installing user's uid. It never runs a
// caller-chosen command or path, and restart-charon refuses while any session of
// ours exists.

let paths = NativeHelperPaths.self

/// The one durable log: helper lifecycle lines and charon's own IKE/CFG/KNL
/// output, sanitized, in a root-only directory (0700) and file (0600), rotated
/// by size. A non-root owner reads it only through the control socket's
/// `log-tail`. launchd's stderr file keeps what cannot reach this one: a trap
/// message, or a failure before the log directory exists.
enum HelperLog {
  /// nil when the directory fails its checks: a log directory that is not
  /// root-only would expose charon's lines, so then only stderr is used.
  /// Initialized (lazily and once) by the first line, which top-level code
  /// writes after setting the umask.
  private static let file: NativeRotatingLog? = {
    let path = NativeHelperPaths.logDirectory
    if mkdir(path, 0o700) != 0, errno != EEXIST { return nil }
    var info = stat()
    guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & S_IFMT == S_IFDIR,
      NativeInstallValidation.hasNoACL(path), chmod(path, 0o700) == 0
    else { return nil }
    return NativeRotatingLog(path: NativeHelperPaths.log)
  }()

  /// A helper line the rotated log cannot take goes to stderr (launchd's
  /// file, 0644); `echo` sends it there as well. charon lines never do: even
  /// sanitized, they stay in the root-only log or are dropped.
  static func write(_ source: String, _ message: String, echo: Bool = false) {
    let line = NativeHelperLogFormat.line(source: source, message: message)
    let stored = file?.append(line) == true
    if source != "charon", !stored || echo {
      FileHandle.standardError.write(Data((line + "\n").utf8))
    }
  }

  static func tail(lines: Int) -> [String] { file?.tail(lines: lines) ?? [] }
}

func log(_ message: String) {
  HelperLog.write("helper", message)
}

func fail(_ message: String) -> Never {
  HelperLog.write("helper", "fatal: " + message, echo: true)
  exit(1)
}

struct OwnedRoute: Equatable {
  let host: String
  let interface: String
  let ike: String
}

final class Helper: @unchecked Sendable {
  private let lock = NSLock()
  private let allowedHosts: Set<String>
  private let routeLock = NSLock()
  private var charon: Process?
  private var routes: [String: OwnedRoute] = [:]
  private var absenceCounts: [String: Int] = [:]
  private var restartDelay: TimeInterval = 1
  private var stopping = false
  /// Set while a requested restart is in flight, so charonExited neither
  /// doubles the crash backoff nor waits for it.
  private var restartRequested = false
  private var governor = NativeCharonRestartGovernor()
  /// pid of the charon whose VICI socket was verified and tightened.
  private var readyPID: pid_t?

  init(allowedHosts: Set<String>) {
    self.allowedHosts = allowedHosts
  }

  // MARK: charon

  func startCharon() {
    lock.lock()
    guard !stopping, charon?.isRunning != true else {
      lock.unlock()
      return
    }
    try? FileManager.default.removeItem(atPath: paths.charonVICI)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: paths.charon)
    process.environment = [
      "STRONGSWAN_CONF": paths.configuration,
      "OPENSSL_CONF": paths.runtime + "/etc/powervpn-openssl.cnf",
      "OPENSSL_MODULES": paths.opensslEmpty,
      "OPENSSL_ENGINES": paths.opensslEmpty,
      "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    ]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    // charon's own log (IKE, CFG, KNL; see strongswan.conf) is drained here,
    // sanitized and written to the helper's rotated log. A pipe nobody reads
    // would stall charon, so the reader runs until EOF.
    let errors = Pipe()
    process.standardError = errors
    process.terminationHandler = { [weak self] finished in
      self?.charonExited(finished)
    }
    do {
      try process.run()
    } catch {
      lock.unlock()
      try? errors.fileHandleForWriting.close()
      try? errors.fileHandleForReading.close()
      log("charon failed to start")
      scheduleRestart()
      return
    }
    charon = process
    lock.unlock()
    // The child holds the write end now; ours must close for EOF to arrive.
    try? errors.fileHandleForWriting.close()
    log("charon started pid=\(process.processIdentifier)")
    // The reader owns a duplicate, so the Pipe object's own close cannot
    // pull the descriptor out from under it.
    let reader = dup(errors.fileHandleForReading.fileDescriptor)
    try? errors.fileHandleForReading.close()
    if reader >= 0 {
      Thread.detachNewThread { drainCharonLog(reader) }
    } else {
      log("charon log pipe unavailable; stopping charon")
      process.terminate()
    }
    DispatchQueue.global().async { [self] in checkVICISocket(process) }
  }

  private func checkVICISocket(_ process: Process) {
    for _ in 0..<80 {
      guard lock.withLock({ charon === process && process.isRunning && !stopping }) else { return }
      var info = stat()
      if lstat(paths.charonVICI, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK {
        // strongSwan creates Unix sockets as 0660. The enclosing directory is
        // root-only from before spawn, so tightening to 0600 has no access gap.
        guard info.st_uid == 0, chmod(paths.charonVICI, 0o600) == 0 else {
          log("unsafe charon socket; stopping")
          process.terminate()
          return
        }
        lock.withLock {
          restartDelay = 1
          readyPID = process.processIdentifier
        }
        log("vici socket ready")
        return
      }
      usleep(100_000)
    }
    log("vici socket did not appear; restarting charon")
    if lock.withLock({ charon === process && process.isRunning }) { process.terminate() }
  }

  private func charonExited(_ process: Process) {
    guard lock.withLock({ charon === process }) else { return }
    let requested = lock.withLock { restartRequested }
    log(
      "charon exited status=\(process.terminationStatus) reason=\(process.terminationReason == .exit ? "exit" : "signal")"
        + (requested ? " (restart requested)" : ""))
    // Every owned route pointed into charon's utun, which is gone with it.
    deleteAllRoutes(reason: "charon_exited")
    lock.withLock {
      charon = nil
      readyPID = nil
      restartRequested = false
    }
    if requested {
      DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { [self] in startCharon() }
    } else {
      scheduleRestart()
    }
  }

  private func scheduleRestart() {
    let delay = lock.withLock { () -> TimeInterval? in
      guard !stopping else { return nil }
      let delay = restartDelay
      restartDelay = min(restartDelay * 2, 60)
      return delay
    }
    guard let delay else { return }
    DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [self] in startCharon() }
  }

  var charonRunning: Bool { lock.withLock { charon?.isRunning == true } }

  /// True once the running charon's VICI socket is verified.
  private var charonReady: Bool {
    lock.withLock {
      guard let charon, charon.isRunning else { return false }
      return readyPID == charon.processIdentifier
    }
  }

  /// nil when idleness cannot be proven. Idle means: no route we own, and
  /// charon holds no IKE SA, connection or key of ours. A restart drops all of
  /// them, so unreadable state counts as "not provably idle".
  private func charonIsIdle() -> Bool? {
    if !routeHosts.isEmpty { return false }
    guard charonRunning else { return true }
    guard let session = try? VICISession(socketPath: paths.charonVICI, timeoutMilliseconds: 3_000)
    else { return nil }
    defer { session.close() }
    guard let names = try? nativeSessionNames(session) else { return nil }
    return names.isEmpty
  }

  /// Restarts charon on request of the owner, only while idle and within the
  /// governor's budget. Replies once the new charon's VICI socket is ready, so
  /// the caller can retry immediately.
  func restartCharon() -> NativeHelperResponse {
    let decision = routeLock.withLock { () -> NativeCharonRestartGovernor.Decision in
      let idle = charonIsIdle()
      return lock.withLock { governor.request(now: Date(), idle: idle) }
    }
    if case .refuse(let reason) = decision {
      log("restart-charon refused: \(reason.rawValue)")
      return NativeHelperResponse(ok: false, error: "restart_refused_\(reason.rawValue)")
    }
    let process = lock.withLock { () -> Process? in
      guard !stopping else { return nil }
      restartRequested = true
      return charon
    }
    log("restart-charon granted (owner request; charon idle)")
    if let process, process.isRunning {
      process.terminate()
      for _ in 0..<100 where process.isRunning { usleep(100_000) }
      if process.isRunning {
        kill(process.processIdentifier, SIGKILL)
        for _ in 0..<30 where process.isRunning { usleep(100_000) }
      }
    } else {
      lock.withLock { restartRequested = false }
      startCharon()
    }
    for _ in 0..<150 {
      if charonReady {
        log("restart-charon complete")
        return NativeHelperResponse(ok: true, charonRunning: true)
      }
      usleep(100_000)
    }
    log("restart-charon: charon not ready after 15 s")
    return NativeHelperResponse(ok: false, error: "restart_not_ready")
  }

  func stop() {
    let process = lock.withLock { () -> Process? in
      stopping = true
      return charon
    }
    deleteAllRoutes(reason: "helper_stopping")
    guard let process, process.isRunning else { return }
    process.terminate()
    for _ in 0..<100 where process.isRunning { usleep(100_000) }
    if process.isRunning { kill(process.processIdentifier, SIGKILL) }
  }

  // MARK: routes

  private func listIKE(_ name: String) -> NativeIKELookup {
    guard let session = try? VICISession(socketPath: paths.charonVICI, timeoutMilliseconds: 3_000)
    else { return .unknown }
    defer { session.close() }
    guard
      let result = try? session.streamedRequest(
        command: "list-sas", event: "list-sa",
        message: VICIMessage(elements: [.keyValue("ike", name)]))
    else { return .unknown }
    if let summary = NativeIKESummary.parse(result.events).first(where: { $0.name == name }) {
      return .present(summary)
    }
    return .absent
  }

  func addRoute(ike: String, host: String) -> NativeHelperResponse {
    routeLock.lock()
    defer { routeLock.unlock() }
    guard NativeVICIAllowlist.validSessionName(ike) else {
      return NativeHelperResponse(ok: false, error: "ike_name_invalid")
    }
    guard let address = parseStrictIPv4(host), nativeRoutableHost(address) else {
      return NativeHelperResponse(ok: false, error: "host_not_routable")
    }
    guard allowedHosts.contains(host) else {
      return NativeHelperResponse(ok: false, error: "host_not_authorized")
    }
    guard case .present(let summary) = listIKE(ike), summary.state == "ESTABLISHED",
      summary.hasInstalledChild
    else { return NativeHelperResponse(ok: false, error: "child_not_installed") }
    guard summary.remoteHost != host else {
      return NativeHelperResponse(ok: false, error: "host_is_gateway")
    }
    guard let vip = summary.localVirtualIPs.first(where: { parseStrictIPv4($0) != nil }),
      let interface = utunInterface(holding: vip)
    else { return NativeHelperResponse(ok: false, error: "virtual_ip_interface_missing") }

    if let existing = lock.withLock({ routes[host] }) {
      if existing.interface == interface, existing.ike == ike {
        return NativeHelperResponse(ok: true, interface: interface)
      }
      return NativeHelperResponse(ok: false, error: "host_route_owned_by_other_session")
    }
    guard route(["-n", "add", "-host", host, "-interface", interface]) else {
      return NativeHelperResponse(ok: false, error: "route_add_failed")
    }
    lock.withLock {
      routes[host] = OwnedRoute(host: host, interface: interface, ike: ike)
    }
    log("route add \(host) -> \(interface) for \(ike)")
    return NativeHelperResponse(ok: true, interface: interface)
  }

  func deleteRoute(host: String) -> NativeHelperResponse {
    routeLock.lock()
    defer { routeLock.unlock() }
    guard let owned = lock.withLock({ routes[host] }) else {
      return NativeHelperResponse(ok: true)
    }
    return removeRoute(owned, reason: "requested")
      ? NativeHelperResponse(ok: true)
      : NativeHelperResponse(ok: false, error: "route_delete_failed")
  }

  @discardableResult
  private func removeRoute(_ owned: OwnedRoute, reason: String) -> Bool {
    // A failed route query is not proof that our route disappeared.
    let current = hostRouteInterface(owned.host)
    guard current != .unknown else { return false }
    if current == .interface(owned.interface) {
      guard route(["-n", "delete", "-host", owned.host, "-interface", owned.interface]) else {
        return false
      }
    }
    lock.withLock { _ = routes.removeValue(forKey: owned.host) }
    absenceCounts.removeValue(forKey: owned.host)
    log("route delete \(owned.host) (\(reason))")
    return true
  }

  private func deleteAllRoutes(reason: String) {
    routeLock.lock()
    defer { routeLock.unlock() }
    for owned in lock.withLock({ Array(routes.values) }) { removeRoute(owned, reason: reason) }
  }

  /// Only authoritative absence removes a route. Busy or unreachable charon,
  /// and a temporarily missing CHILD during rekey, leave ownership intact.
  func reconcile() {
    routeLock.lock()
    defer { routeLock.unlock() }
    for owned in lock.withLock({ Array(routes.values) }) {
      if listIKE(owned.ike).confirmsAbsence {
        absenceCounts[owned.host, default: 0] += 1
        if absenceCounts[owned.host, default: 0] >= 2 { removeRoute(owned, reason: "sa_gone") }
      } else {
        absenceCounts.removeValue(forKey: owned.host)
      }
    }
  }

  var routeHosts: [String] { lock.withLock { routes.keys.sorted() } }
}

func route(_ arguments: [String]) -> Bool {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/sbin/route")
  process.arguments = arguments
  process.standardOutput = FileHandle.nullDevice
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return false }
  process.waitUntilExit()
  return process.terminationStatus == 0
}

enum HostRouteLookup: Equatable {
  case interface(String)
  case absent, unknown
}

func hostRouteInterface(_ host: String) -> HostRouteLookup {
  let process = Process()
  let pipe = Pipe()
  process.executableURL = URL(fileURLWithPath: "/sbin/route")
  process.arguments = ["-n", "get", "-host", host]
  process.standardOutput = pipe
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return .unknown }
  let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
  process.waitUntilExit()
  var destination: String?
  var interface: String?
  for line in output.split(separator: "\n") {
    let parts = line.split(separator: ":", maxSplits: 1).map {
      $0.trimmingCharacters(in: .whitespaces)
    }
    guard parts.count == 2 else { continue }
    if parts[0] == "destination" { destination = parts[1] }
    if parts[0] == "interface" { interface = parts[1] }
  }
  guard process.terminationStatus == 0, let destination, let interface else { return .unknown }
  return destination == host ? .interface(interface) : .absent
}

func utunInterface(holding ipv4: String) -> String? {
  guard let wanted = parseStrictIPv4(ipv4) else { return nil }
  var head: UnsafeMutablePointer<ifaddrs>?
  guard getifaddrs(&head) == 0 else { return nil }
  defer { freeifaddrs(head) }
  var cursor = head
  while let entry = cursor {
    defer { cursor = entry.pointee.ifa_next }
    guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET)
    else { continue }
    let name = String(cString: entry.pointee.ifa_name)
    guard name.hasPrefix("utun") else { continue }
    let value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
      UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
    }
    if value == wanted { return name }
  }
  return nil
}

// MARK: log

/// Reads charon's stderr until EOF (charon exited). Lines are capped, sanitized
/// and rate-limited so a log flood cannot turn into unbounded disk churn.
/// read(2), not FileHandle.availableData: that raises an Objective-C exception
/// on a read error, which would take the root daemon down. If this reader
/// stopped while charon ran, charon would block on a full pipe.
func drainCharonLog(_ descriptor: Int32) {
  var pending = Data()
  var windowStart = Date()
  var inWindow = 0
  var dropped = 0
  func emit(_ lineData: Data) {
    let now = Date()
    if now.timeIntervalSince(windowStart) >= 10 {
      if dropped > 0 { log("dropped \(dropped) charon log lines (rate limit)") }
      windowStart = now
      inWindow = 0
      dropped = 0
    }
    inWindow += 1
    guard inWindow <= 500 else {
      dropped += 1
      return
    }
    HelperLog.write("charon", String(decoding: lineData.prefix(2_000), as: UTF8.self))
  }
  var buffer = [UInt8](repeating: 0, count: 8_192)
  while true {
    let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
    if count < 0, errno == EINTR { continue }
    if count <= 0 { break }
    pending.append(contentsOf: buffer[0..<count])
    while let newline = pending.firstIndex(of: 0x0A) {
      emit(pending[pending.startIndex..<newline])
      pending.removeSubrange(pending.startIndex...newline)
    }
    if pending.count > 8_192 {
      emit(pending)
      pending.removeAll()
    }
  }
  if !pending.isEmpty { emit(pending) }
  close(descriptor)
}

/// The newest `lines` (default 80, at most 200) lines, optionally only those at
/// or after `since`. Every stored line was sanitized when written.
func tailLog(lines: Int?, since: Double?) -> [String] {
  let count = min(max(lines ?? 80, 1), NativeHelperRequest.maximumLogLines)
  let all = HelperLog.tail(lines: since == nil ? count : 2_000)
  return NativeHelperLogFormat.recent(all, sinceEpoch: since, count: count)
}

// MARK: control socket

func serveControl(_ helper: Helper, owner: uid_t) {
  unlink(paths.control)
  let fd = socket(AF_UNIX, SOCK_STREAM, 0)
  guard fd >= 0, var address = unixAddress(paths.control) else { fail("control socket") }
  let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
  }
  guard bound == 0, listen(fd, 8) == 0 else { fail("control bind") }
  guard chown(paths.control, owner, 0) == 0, chmod(paths.control, 0o600) == 0 else {
    fail("control permissions")
  }
  log("control socket ready")
  let slots = DispatchSemaphore(value: 8)
  while true {
    let client = accept(fd, nil, nil)
    if client < 0 { continue }
    guard slots.wait(timeout: .now()) == .success else {
      close(client)
      continue
    }
    DispatchQueue.global().async {
      defer {
        close(client)
        slots.signal()
      }
      var uid: uid_t = 0
      var gid: gid_t = 0
      guard getpeereid(client, &uid, &gid) == 0, uid == owner || uid == 0 else { return }
      var timeout = timeval(tv_sec: 10, tv_usec: 0)
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
      setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
      guard let line = readLine(client, limit: 4_096),
        let request = try? JSONDecoder().decode(NativeHelperRequest.self, from: line)
      else { return }
      let response: NativeHelperResponse
      switch request.op {
      case .status:
        response = NativeHelperResponse(
          ok: true, charonRunning: helper.charonRunning, routes: helper.routeHosts,
          capabilities: [
            NativeHelperResponse.logTailCapability, NativeHelperResponse.restartCharonCapability,
          ])
      case .logTail:
        response = NativeHelperResponse(
          ok: true, logLines: tailLog(lines: request.lines, since: request.sinceEpoch))
      case .restartCharon:
        response = helper.restartCharon()
      case .routeAdd:
        if let ike = request.ike, let host = request.host {
          response = helper.addRoute(ike: ike, host: host)
        } else {
          response = NativeHelperResponse(ok: false, error: "request_invalid")
        }
      case .routeDelete:
        if let host = request.host {
          response = helper.deleteRoute(host: host)
        } else {
          response = NativeHelperResponse(ok: false, error: "request_invalid")
        }
      }
      guard var data = try? JSONEncoder().encode(response) else { return }
      data.append(0x0A)
      _ = writeAll(client, data)
    }
  }
}

// MARK: serving

/// A charon outlives a helper that died without stopping it (a crash, SIGKILL):
/// it runs in its own process group, so launchd does not take it down with the
/// helper, and every later charon finds its pid alive in the pidfile and exits
/// with status 66. Only a root process executed as this runtime's charon is
/// stopped. If it does not exit, or the pid cannot be inspected, this fails
/// and keeps the pidfile rather than let a second charon start.
func stopStrayCharon() {
  let text: String
  do {
    text = try String(contentsOfFile: paths.charonPID, encoding: .utf8)
  } catch CocoaError.fileReadNoSuchFile {
    return
  } catch {
    fail("cannot read the charon pidfile")
  }
  if let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 {
    switch ProcessIdentity.lookup(pid) {
    case .running(let stray) where stray.uid == 0 && stray.executedPath == paths.charon:
      log("stopping stray charon pid=\(pid)")
      guard stray.stop() else { fail("stray charon pid=\(pid) did not exit") }
    case .running, .gone:
      break
    case .unknown:
      fail("cannot inspect pid \(pid) from the charon pidfile")
    }
  }
  // charon itself discards a pidfile whose pid is gone, but not one whose pid
  // another process has reused since.
  unlink(paths.charonPID)
}

final class WakeWatcher: @unchecked Sendable {
  private let lock = NSLock()
  private var detector = NativeWakeDetector()

  func tick() {
    let slept = lock.withLock {
      detector.observe(
        uptimeNanoseconds: clock_gettime_nsec_np(CLOCK_UPTIME_RAW),
        continuousNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))
    }
    if let slept { log("wake detected: the Mac slept about \(Int(slept)) s") }
  }
}

/// Top-level code is main-actor isolated, and so is any non-Sendable closure
/// written in it, such as a dispatch source handler. Run on a global queue,
/// that closure fails Swift 6's runtime isolation check and traps the daemon,
/// leaving charon behind. Everything handed to other queues is therefore set
/// up in this nonisolated function. The caller keeps the returned sources:
/// a released source stops firing.
func startBackgroundWork(_ helper: Helper, owner: uid_t) -> [any DispatchSourceProtocol] {
  var sources: [any DispatchSourceProtocol] = []
  for number in [SIGTERM, SIGINT, SIGHUP] {
    signal(number, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
    source.setEventHandler {
      log("signal \(number); stopping")
      helper.stop()
      unlink(paths.control)
      unlink(paths.vici)
      exit(0)
    }
    source.resume()
    sources.append(source)
  }

  stopStrayCharon()
  helper.startCharon()
  let reconcileTimer = DispatchSource.makeTimerSource(queue: .global())
  reconcileTimer.schedule(deadline: .now() + 5, repeating: 5)
  // Only logged, never acted on: it lets a later failure be correlated with
  // a sleep/wake that charon's kernel-interface cache may not have survived.
  let wake = WakeWatcher()
  reconcileTimer.setEventHandler {
    helper.reconcile()
    wake.tick()
  }
  reconcileTimer.resume()
  sources.append(reconcileTimer)

  DispatchQueue.global().async { serveVICI(owner: owner) }
  return sources
}

/// install.sh: the allowed-hosts list for a targets.json on stdin. Kept out of
/// top-level code, whose closures (even `map(\.host)`) are main-actor isolated
/// and carry runtime isolation checks on older compilers.
func printHostPolicy() -> Never {
  struct Target: Decodable { let host: String }
  struct Configuration: Decodable { let targets: [String: Target] }
  guard let data = try? FileHandle.standardInput.read(upToCount: 1_048_577),
    data.count <= 1_048_576,
    let configuration = try? JSONDecoder().decode(Configuration.self, from: data),
    let hosts = NativeHostPolicy.parse(
      configuration.targets.values.map(\.host).joined(separator: "\n"))
  else { fail("invalid target host policy") }
  print(hosts.sorted().joined(separator: "\n"))
  exit(0)
}

// MARK: entry

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "verify-install" {
  exit(NativeInstallValidation.validateTree(CommandLine.arguments[2]) ? 0 : 1)
}
if CommandLine.arguments.dropFirst() == ["host-policy"] { printHostPolicy() }
// uninstall.sh, after bootout: the same stray-charon rule as at startup.
if CommandLine.arguments.dropFirst() == ["stop-stray-charon"] {
  guard geteuid() == 0 else { fail("must run as root") }
  stopStrayCharon()
  exit(0)
}
guard CommandLine.arguments.dropFirst() == ["serve"] else {
  FileHandle.standardError.write(Data("usage: powervpn-native-helper serve (as root)\n".utf8))
  exit(64)
}
guard geteuid() == 0 else { fail("must run as root") }
guard NativeInstallValidation.validateTree(paths.home) else {
  fail("unsafe install tree; reinstall the native backend")
}
guard
  let ownerText = try? String(contentsOfFile: paths.owner, encoding: .utf8)
    .trimmingCharacters(in: .whitespacesAndNewlines),
  let ownerValue = UInt32(ownerText), ownerValue != 0
else { fail("owner-uid missing") }
let owner = uid_t(ownerValue)

// umask applies before charon binds: there is no world-accessible socket window.
umask(0o077)
log("helper starting pid=\(getpid()) owner=\(owner)")
if mkdir(paths.runDirectory, 0o755) != 0, errno != EEXIST { fail("runtime directory") }
var runInfo = stat()
guard lstat(paths.runDirectory, &runInfo) == 0, runInfo.st_uid == 0,
  runInfo.st_mode & S_IFMT == S_IFDIR, runInfo.st_mode & 0o022 == 0,
  NativeInstallValidation.hasNoACL(paths.runDirectory), chmod(paths.runDirectory, 0o755) == 0
else { fail("unsafe runtime directory") }
if mkdir(paths.privateRunDirectory, 0o700) != 0, errno != EEXIST {
  fail("private runtime directory")
}
guard lstat(paths.privateRunDirectory, &runInfo) == 0, runInfo.st_uid == 0,
  runInfo.st_mode & S_IFMT == S_IFDIR, runInfo.st_mode & 0o777 == 0o700,
  NativeInstallValidation.hasNoACL(paths.privateRunDirectory)
else { fail("unsafe private runtime directory") }
guard let policy = try? String(contentsOfFile: paths.allowedHosts, encoding: .utf8),
  let allowedHosts = NativeHostPolicy.parse(policy)
else { fail("allowed-hosts missing or invalid; reinstall") }

signal(SIGPIPE, SIG_IGN)
let helper = Helper(allowedHosts: allowedHosts)
// A global lives as long as the process, and so do the sources it holds.
let backgroundSources = startBackgroundWork(helper, owner: owner)
serveControl(helper, owner: owner)
