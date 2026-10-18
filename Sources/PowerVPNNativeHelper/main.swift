import Darwin
import Foundation
import PowerVPNCore

// Root LaunchDaemon for the native backend.
//
// It owns two things the user-level CLI cannot do itself:
//   1. keep the patched charon running, with its VICI socket handed to the
//      installing user;
//   2. add one host route per tunnel into charon's virtual-IP utun, and take it
//      away again when asked or when the IKE SA behind it is gone.
// The control socket accepts status/route-add/route-delete only, from the
// installing user's uid. It never runs a caller-chosen command or path.

let paths = NativeHelperPaths.self

func log(_ message: String) {
  let line = "\(ISO8601DateFormatter().string(from: Date())) \(message)\n"
  FileHandle.standardError.write(Data(line.utf8))
}

func fail(_ message: String) -> Never {
  log("fatal: " + message)
  exit(1)
}

struct OwnedRoute: Codable, Equatable {
  let host: String
  let interface: String
  let ike: String
}

final class Helper: @unchecked Sendable {
  private let lock = NSLock()
  private let owner: uid_t
  private var charon: Process?
  private var routes: [String: OwnedRoute] = [:]
  private var restartDelay: TimeInterval = 1
  private var stopping = false

  init(owner: uid_t) {
    self.owner = owner
  }

  // MARK: charon

  func startCharon() {
    lock.lock()
    defer { lock.unlock() }
    guard !stopping, charon?.isRunning != true else { return }
    try? FileManager.default.removeItem(atPath: paths.vici)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: paths.charon)
    process.environment = [
      "STRONGSWAN_CONF": paths.configuration,
      "OPENSSL_CONF": paths.runtime + "/etc/powervpn-openssl.cnf",
      "OPENSSL_MODULES": paths.runtime + "/lib/ossl-modules",
      "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    ]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    process.terminationHandler = { [weak self] finished in
      self?.charonExited(status: finished.terminationStatus)
    }
    do {
      try process.run()
    } catch {
      log("charon failed to start")
      scheduleRestart()
      return
    }
    charon = process
    log("charon started pid=\(process.processIdentifier)")
    DispatchQueue.global().async { [self] in handOverVICISocket(pid: process.processIdentifier) }
  }

  private func handOverVICISocket(pid: Int32) {
    for _ in 0..<80 {
      var info = stat()
      if lstat(paths.vici, &info) == 0, info.st_mode & S_IFMT == S_IFSOCK {
        chown(paths.vici, owner, 0)
        chmod(paths.vici, 0o600)
        lock.withLock { restartDelay = 1 }
        log("vici socket ready")
        return
      }
      usleep(100_000)
    }
    log("vici socket did not appear; restarting charon")
    kill(pid, SIGTERM)
  }

  private func charonExited(status: Int32) {
    log("charon exited status=\(status)")
    // Every owned route pointed into charon's utun, which is gone with it.
    deleteAllRoutes(reason: "charon_exited")
    lock.withLock { charon = nil }
    scheduleRestart()
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

  private func listIKE(_ name: String) -> NativeIKESummary? {
    guard let session = try? VICISession(socketPath: paths.vici, timeoutMilliseconds: 3_000)
    else { return nil }
    defer { session.close() }
    guard
      let result = try? session.streamedRequest(
        command: "list-sas", event: "list-sa",
        message: VICIMessage(elements: [.keyValue("ike", name), .keyValue("noblock", "yes")]))
    else { return nil }
    return NativeIKESummary.parse(result.events).first { $0.name == name }
  }

  func addRoute(ike: String, host: String) -> NativeHelperResponse {
    guard ike.utf8.count <= 128, ike.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
      return NativeHelperResponse(ok: false, error: "ike_name_invalid")
    }
    guard let address = parseStrictIPv4(host), nativeRoutableHost(address) else {
      return NativeHelperResponse(ok: false, error: "host_not_routable")
    }
    guard let summary = listIKE(ike), summary.state == "ESTABLISHED",
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
    guard let owned = lock.withLock({ routes[host] }) else {
      return NativeHelperResponse(ok: true)
    }
    return removeRoute(owned, reason: "requested")
      ? NativeHelperResponse(ok: true)
      : NativeHelperResponse(ok: false, error: "route_delete_failed")
  }

  @discardableResult
  private func removeRoute(_ owned: OwnedRoute, reason: String) -> Bool {
    // Delete only if the host route still points at our interface.
    if hostRouteInterface(owned.host) == owned.interface {
      guard route(["-n", "delete", "-host", owned.host, "-interface", owned.interface]) else {
        return false
      }
    }
    lock.withLock { _ = routes.removeValue(forKey: owned.host) }
    log("route delete \(owned.host) (\(reason))")
    return true
  }

  private func deleteAllRoutes(reason: String) {
    for owned in lock.withLock({ Array(routes.values) }) { removeRoute(owned, reason: reason) }
  }

  /// Drops routes whose IKE SA or utun no longer exists.
  func reconcile() {
    for owned in lock.withLock({ Array(routes.values) }) {
      let summary = listIKE(owned.ike)
      let alive =
        summary?.hasInstalledChild == true
        && summary.map { s in
          s.localVirtualIPs.contains { utunInterface(holding: $0) == owned.interface }
        } == true
      if !alive { removeRoute(owned, reason: "sa_gone") }
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

func hostRouteInterface(_ host: String) -> String? {
  let process = Process()
  let pipe = Pipe()
  process.executableURL = URL(fileURLWithPath: "/sbin/route")
  process.arguments = ["-n", "get", "-host", host]
  process.standardOutput = pipe
  process.standardError = FileHandle.nullDevice
  guard (try? process.run()) != nil else { return nil }
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
  return destination == host ? interface : nil
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
  chown(paths.control, owner, 0)
  chmod(paths.control, 0o600)
  log("control socket ready")
  while true {
    let client = accept(fd, nil, nil)
    if client < 0 { continue }
    DispatchQueue.global().async {
      defer { close(client) }
      var uid: uid_t = 0
      var gid: gid_t = 0
      guard getpeereid(client, &uid, &gid) == 0, uid == owner || uid == 0 else { return }
      var timeout = timeval(tv_sec: 10, tv_usec: 0)
      setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
      guard let line = readLine(client, limit: 4_096),
        let request = try? JSONDecoder().decode(NativeHelperRequest.self, from: line)
      else { return }
      let response: NativeHelperResponse
      switch request.op {
      case .status:
        response = NativeHelperResponse(
          ok: true, charonRunning: helper.charonRunning, routes: helper.routeHosts)
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

// MARK: entry

guard CommandLine.arguments.dropFirst() == ["serve"] else {
  FileHandle.standardError.write(Data("usage: powervpn-native-helper serve (as root)\n".utf8))
  exit(64)
}
guard geteuid() == 0 else { fail("must run as root") }
for path in [paths.home, paths.configuration, paths.owner, paths.charon] {
  var info = stat()
  guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & 0o022 == 0 else {
    fail("unsafe or missing install path: \(path)")
  }
}
guard
  let ownerText = try? String(contentsOfFile: paths.owner, encoding: .utf8)
    .trimmingCharacters(in: .whitespacesAndNewlines),
  let ownerValue = UInt32(ownerText), ownerValue != 0
else { fail("owner-uid missing") }
let owner = uid_t(ownerValue)

mkdir(paths.runDirectory, 0o755)
chown(paths.runDirectory, 0, 0)
chmod(paths.runDirectory, 0o755)

signal(SIGPIPE, SIG_IGN)
let helper = Helper(owner: owner)
var signalSources: [DispatchSourceSignal] = []
for number in [SIGTERM, SIGINT, SIGHUP] {
  signal(number, SIG_IGN)
  let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
  source.setEventHandler {
    log("signal \(number); stopping")
    helper.stop()
    unlink(paths.control)
    exit(0)
  }
  source.resume()
  signalSources.append(source)
}

helper.startCharon()
let reconcileTimer = DispatchSource.makeTimerSource(queue: .global())
reconcileTimer.schedule(deadline: .now() + 5, repeating: 5)
reconcileTimer.setEventHandler { helper.reconcile() }
reconcileTimer.resume()

serveControl(helper, owner: owner)
