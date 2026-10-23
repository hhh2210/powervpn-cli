import Darwin
import Foundation
import PowerVPNProduct

enum UserProductProcessIO: Equatable, Sendable {
  case inherited
  case captured
  case discarded
}

struct UserProductProcessResult: Equatable, Sendable {
  let started: Bool
  let exitCode: Int32
  let output: String
}

protocol UserProductProcessRunning: Sendable {
  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult
}

struct FoundationUserProductProcessRunner: UserProductProcessRunning {
  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    var capture: Pipe?
    switch io {
    case .inherited:
      process.standardInput = FileHandle.standardInput
      process.standardOutput = FileHandle.standardOutput
      process.standardError = FileHandle.standardError
    case .captured:
      let pipe = Pipe()
      capture = pipe
      process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
      process.standardOutput = pipe
      process.standardError = pipe
    case .discarded:
      process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
      process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
      process.standardError = FileHandle(forWritingAtPath: "/dev/null")
    }
    do {
      try process.run()
    } catch {
      return UserProductProcessResult(started: false, exitCode: 70, output: "")
    }
    let data = capture?.fileHandleForReading.readDataToEndOfFile() ?? Data()
    process.waitUntilExit()
    let exitCode: Int32
    if process.terminationReason == .uncaughtSignal {
      exitCode = min(255, 128 + process.terminationStatus)
    } else {
      exitCode = min(255, max(0, process.terminationStatus))
    }
    return UserProductProcessResult(
      started: true,
      exitCode: exitCode,
      output: String(decoding: data.prefix(64 * 1_024), as: UTF8.self)
    )
  }
}

struct UserProductSSHEffectiveConfiguration: Equatable, Sendable {
  let hostname: String
  let user: String
  let port: UInt16
  let controlMaster: String
  let controlPath: String

  static func parse(_ output: String) -> Self? {
    var values: [String: String] = [:]
    for line in output.split(separator: "\n") {
      let parts = line.split(separator: " ", maxSplits: 1)
      guard parts.count == 2 else { continue }
      let key = String(parts[0])
      if ["hostname", "user", "port", "controlmaster", "controlpath"].contains(key) {
        values[key] = String(parts[1])
      }
    }
    guard let hostname = values["hostname"],
      let user = values["user"],
      let portText = values["port"],
      let port = UInt16(portText), port > 0,
      let controlMaster = values["controlmaster"],
      let controlPath = values["controlpath"],
      controlPath.hasPrefix("/"), controlPath != "none"
    else { return nil }
    return Self(
      hostname: hostname,
      user: user,
      port: port,
      controlMaster: controlMaster,
      controlPath: controlPath
    )
  }
}

enum UserProductSSHArguments {
  static func configuration(target: String) -> [String] {
    ["-G", target]
  }

  static func ephemeral(
    target: String,
    executablePath: String,
    sessionID: String,
    remoteCommand: [String]
  ) -> [String] {
    var arguments = [
      "-o", "ControlMaster=no",
      "-o", "ControlPath=none",
      "-o", "ControlPersist=no",
      "-o",
      "ProxyCommand=\(proxyCommand(executablePath, ["internal-session-proxy", sessionID, target, "%h", "%p"]))",
      target,
    ]
    arguments.append(contentsOf: remoteCommand)
    return arguments
  }

  /// `diagnosticLog` receives ssh's own errors (`-E`), at LogLevel ERROR and without LogVerbose
  /// whatever ~/.ssh/config says: QUIET would hide the refusal, and DEBUG or a LogVerbose pattern
  /// would bury it past the read limit. Without a log they are discarded.
  static func startMaster(
    target: String,
    controlPath: String,
    executablePath: String,
    sessionID: String,
    diagnosticLog: String? = nil
  ) -> [String] {
    (diagnosticLog.map { ["-E", $0, "-o", "LogLevel=ERROR", "-o", "LogVerbose=none"] } ?? []) + [
      "-M", "-N", "-f",
      "-S", controlPath,
      "-o", "ControlMaster=yes",
      "-o", "ControlPersist=no",
      "-o", "BatchMode=yes",
      "-o", "RequestTTY=no",
      "-o", "ServerAliveInterval=15",
      "-o", "ServerAliveCountMax=3",
      "-o", "ConnectTimeout=60",
      "-o",
      "ProxyCommand=\(proxyCommand(executablePath, ["internal-session-proxy", sessionID, target, "%h", "%p"]))",
      target,
    ]
  }

  static func checkMaster(target: String, controlPath: String) -> [String] {
    ["-S", controlPath, "-O", "check", target]
  }

  static func stopMaster(target: String, controlPath: String) -> [String] {
    ["-S", controlPath, "-O", "exit", target]
  }

  static func useMaster(
    target: String,
    controlPath: String,
    remoteCommand: [String]
  ) -> [String] {
    var arguments = ["-S", controlPath, "-o", "ControlMaster=no", target]
    arguments.append(contentsOf: remoteCommand)
    return arguments
  }

  private static func proxyCommand(_ executablePath: String, _ arguments: [String]) -> String {
    ([executablePath] + arguments).map(shellQuote).joined(separator: " ")
  }

  private static func shellQuote(_ value: String) -> String {
    if value == "%h" || value == "%p" { return value }
    return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}

func userProductMasterPID(_ output: String) -> Int? {
  guard let range = output.range(of: "pid=") else { return nil }
  let digits = output[range.upperBound...].prefix { $0.isNumber }
  return Int(digits)
}

func removeOwnedStaleControlSocket(_ path: String) -> Bool {
  var metadata = stat()
  guard lstat(path, &metadata) == 0 else { return errno == ENOENT }
  guard metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFSOCK else {
    return false
  }
  return Darwin.unlink(path) == 0
}

/// ssh's own messages while it starts a master, through a FIFO that `ssh -E` writes to.
///
/// The master's stderr cannot be captured instead: ssh hands it to the ProxyCommand, which keeps
/// it open for the whole session. A regular file would not do either: the master keeps its log
/// descriptor for the whole session and appends every later error to it. Here a thread drains the
/// FIFO while the start runs, and `close()` closes it once the start is decided; the master's
/// later writes then fail with EPIPE, which ssh ignores (it ignores SIGPIPE), so nothing reaches
/// the disk. The messages can name the user and host, so they are only classified, never printed.
/// Every instance must be closed.
final class UserProductSSHDiagnosticPipe: @unchecked Sendable {
  static let limitBytes = 16 * 1_024
  private static let namePrefix = "ssh-master-"
  private static let nameSuffix = ".fifo"
  /// How long the drain thread waits for data before it checks whether to stop.
  private static let pollMilliseconds: Int32 = 50

  let path: String
  private let reader: Int32
  /// Held until `close()` so the FIFO never reports end-of-file while ssh is not writing.
  private let writer: Int32
  private let draining = DispatchGroup()
  private let lock = NSLock()
  // Guarded by `lock`.
  private var bytes = Data()
  private var stopping = false
  private var closed = false

  /// nil when the FIFO cannot be created; the master then starts with its messages discarded.
  static func create(directory: String) -> UserProductSSHDiagnosticPipe? {
    let path = (directory as NSString).appendingPathComponent(
      namePrefix + UUID().uuidString.lowercased() + nameSuffix)
    guard mkfifo(path, 0o600) == 0 else { return nil }
    // The read end first: ssh's own blocking open for writing then returns at once.
    let reader = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    let writer = reader >= 0 ? open(path, O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC) : -1
    var metadata = stat()
    guard writer >= 0, fstat(reader, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFIFO else {
      if reader >= 0 { Darwin.close(reader) }
      if writer >= 0 { Darwin.close(writer) }
      unlink(path)
      return nil
    }
    return UserProductSSHDiagnosticPipe(path: path, reader: reader, writer: writer)
  }

  private init(path: String, reader: Int32, writer: Int32) {
    self.path = path
    self.reader = reader
    self.writer = writer
    draining.enter()
    // A dispatch read source never fires for a FIFO on macOS, so a thread polls instead.
    let thread = Thread { [self] in
      var descriptor = pollfd(fd: reader, events: Int16(POLLIN), revents: 0)
      while !lock.withLock({ stopping }) {
        if poll(&descriptor, 1, Self.pollMilliseconds) > 0 { readAvailable() }
      }
      draining.leave()
    }
    thread.name = "powervpn.ssh-master-diagnostics"
    thread.start()
  }

  /// Bytes collected so far, at most `limitBytes + 1`.
  var collectedByteCount: Int { lock.withLock { bytes.count } }

  /// The SSH failure the messages name, once ssh has exited; nil when they are over `limitBytes`
  /// or name nothing the classifier knows.
  func failureClass() -> ProductM2SSHFailureClass? {
    stopDraining()
    guard !lock.withLock({ closed }) else { return nil }
    readAvailable()
    return lock.withLock {
      guard bytes.count <= Self.limitBytes else { return nil }
      return bytes.withUnsafeBytes(ProductM2SSHFailureClassifier.classify)
    }
  }

  /// Stops collecting, closes the FIFO and removes it. From then on a master that started gets
  /// EPIPE for every message it logs.
  func close() {
    stopDraining()
    let first = lock.withLock { () -> Bool in
      guard !closed else { return false }
      closed = true
      bytes.resetBytes(in: bytes.indices)
      bytes.removeAll()
      return true
    }
    guard first else { return }
    Darwin.close(reader)
    Darwin.close(writer)
    unlink(path)
  }

  /// Removes the FIFOs of starts that were killed before they removed their own. Only `up` creates
  /// them, and it holds the session command lock, so none of them is still in use.
  static func removeLeftovers(directory: String) {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
    for name in names where name.hasPrefix(namePrefix) && name.hasSuffix(nameSuffix) {
      unlink((directory as NSString).appendingPathComponent(name))
    }
  }

  private func stopDraining() {
    lock.withLock { stopping = true }
    draining.wait()
  }

  /// Keeps the first `limitBytes + 1` bytes and discards the rest, so a chatty ssh never blocks on
  /// a full pipe. Called by the drain thread, and after it stopped by `failureClass()`.
  private func readAvailable() {
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
      let count = read(reader, &buffer, buffer.count)
      guard count > 0 else { return }
      lock.withLock {
        let room = Self.limitBytes + 1 - bytes.count
        if room > 0 { bytes.append(contentsOf: buffer.prefix(min(room, count))) }
      }
    }
  }
}

/// SSH refusals that rerunning cannot fix: the server accepted no key, or ssh will not trust the
/// host key without asking. A background master can neither type a secret nor answer a prompt.
enum UserProductSSHRejection: String, Equatable, Sendable {
  case authRejected = "ssh_auth_rejected"
  case hostKeyRejected = "ssh_host_key_rejected"

  init?(_ failureClass: ProductM2SSHFailureClass) {
    switch failureClass {
    case .authRejected: self = .authRejected
    case .hostKeyRejected: self = .hostKeyRejected
    default: return nil
    }
  }

  func message(target: UserProductTarget) -> String {
    switch self {
    case .authRejected:
      "PowerVPN: \(target.key) rejected SSH public-key login; background SSH cannot type a password or passphrase."
    case .hostKeyRejected:
      "PowerVPN: ssh does not trust the host key of \(target.key) (\(target.host)): it is not in known_hosts or has changed."
    }
  }

  func next(target: UserProductTarget) -> String {
    switch self {
    case .authRejected:
      "install your SSH public key on the server (README step 6, \"把 SSH 公钥装到服务器上\"); if it is already there, README \"出问题时\" covers ssh-agent and IdentitiesOnly"
    case .hostKeyRejected:
      "run `powervpn ssh \(target.key) -- true` and read what ssh reports: accept a new key after checking its fingerprint; for a changed key, confirm the server really changed it, then delete the line ssh names in `Offending ... key in FILE:LINE` and run it again (with StrictHostKeyChecking yes, add the verified key to known_hosts yourself)"
    }
  }
}
