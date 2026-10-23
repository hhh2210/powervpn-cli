import Darwin
import Foundation
import PowerVPNProduct

enum UserProductProcessIO: Equatable, Sendable {
  case inherited
  case captured
  case discarded
  /// As `discarded`, except that standard output goes to `descriptor`, which the caller closes.
  case outputOnly(to: Int32)
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
    case .outputOnly(let descriptor):
      process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
      process.standardOutput = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
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

  /// With `logsToStandardOutput`, ssh writes its own errors (`-E`) to its standard output, at
  /// LogLevel ERROR and without LogVerbose whatever ~/.ssh/config says: QUIET would hide the
  /// refusal, and DEBUG or a LogVerbose pattern would bury it past the read limit. Standard output
  /// because ssh closes every descriptor above standard error when it starts, and hands standard
  /// error on to the ProxyCommand. Otherwise its messages are discarded.
  static func startMaster(
    target: String,
    controlPath: String,
    executablePath: String,
    sessionID: String,
    logsToStandardOutput: Bool = false
  ) -> [String] {
    let logging =
      logsToStandardOutput
      ? ["-E", "/dev/fd/1", "-o", "LogLevel=ERROR", "-o", "LogVerbose=none"] : []
    return logging + [
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

/// ssh's own messages while it starts a master: `ssh -E /dev/fd/1` writes them to its standard
/// output, the write end of this pipe.
///
/// The master's stderr cannot be captured instead: ssh hands it to the ProxyCommand, which keeps
/// it open for the whole session. A file would not do either: the master keeps its log descriptor
/// for the whole session and appends every later error to it. ssh gets the pipe already open, not
/// a path to open, so nothing it does waits for `up`: once the read end is gone (`up` closed it or
/// died), its writes fail with EPIPE, which ssh ignores (it ignores SIGPIPE), and nothing is kept.
/// A thread drains the pipe while the start runs, and `close()` closes it once the start is
/// decided. The messages can name the user and host, so they are only classified, never printed;
/// only the known_hosts line of a changed host key is shown. Every instance must be closed.
final class UserProductSSHDiagnosticPipe: @unchecked Sendable {
  static let limitBytes = 16 * 1_024
  /// How long the drain thread waits for data before it checks whether to stop.
  private static let pollMilliseconds: Int32 = 50

  /// The end ssh gets as its standard output. This copy stays open until `close()`, so the pipe
  /// never reports end-of-file while ssh is not writing.
  let writer: Int32
  private let reader: Int32
  private let draining = DispatchGroup()
  private let lock = NSLock()
  // Guarded by `lock`.
  private var bytes = Data()
  private var stopping = false
  private var closed = false

  /// nil when no pipe can be made; the master then starts with its messages discarded.
  static func create() -> UserProductSSHDiagnosticPipe? {
    var descriptors: [Int32] = [-1, -1]
    guard pipe(&descriptors) == 0 else { return nil }
    // No child inherits either end except as the standard output it is given, and reading never
    // blocks, so draining ends when the pipe is empty even while the ProxyCommand holds a writer.
    guard fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) == 0,
      fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) == 0,
      fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0
    else {
      Darwin.close(descriptors[0])
      Darwin.close(descriptors[1])
      return nil
    }
    return UserProductSSHDiagnosticPipe(reader: descriptors[0], writer: descriptors[1])
  }

  private init(reader: Int32, writer: Int32) {
    self.reader = reader
    self.writer = writer
    draining.enter()
    // A thread rather than a dispatch source, so that `stopDraining()` returns only once nothing
    // reads any more.
    let thread = Thread { [self] in
      var descriptor = pollfd(fd: reader, events: Int16(POLLIN), revents: 0)
      while !lock.withLock({ stopping }) {
        if poll(&descriptor, 1, Self.pollMilliseconds) > 0 { readChunk() }
      }
      draining.leave()
    }
    thread.name = "powervpn.ssh-master-diagnostics"
    thread.start()
  }

  /// Bytes collected so far, at most `limitBytes + 1`.
  var collectedByteCount: Int { lock.withLock { bytes.count } }

  /// The refusal the messages report, once ssh has exited; nil when they are over `limitBytes`
  /// or report none.
  func rejection() -> UserProductSSHRejection? {
    stopDraining()
    guard !lock.withLock({ closed }) else { return nil }
    while collectedByteCount <= Self.limitBytes, readChunk() {}
    return lock.withLock {
      bytes.count <= Self.limitBytes ? UserProductSSHRejection(sshMessages: bytes) : nil
    }
  }

  /// Stops collecting and closes the pipe. From then on a master that started gets EPIPE for every
  /// message it logs.
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
  }

  private func stopDraining() {
    lock.withLock { stopping = true }
    draining.wait()
  }

  /// One read, keeping the first `limitBytes + 1` bytes in all and discarding the rest, so a
  /// chatty ssh never blocks on a full pipe. One read at a time, so the drain thread still sees a
  /// stop request while ssh keeps writing. False once the pipe is empty.
  @discardableResult
  private func readChunk() -> Bool {
    var buffer = [UInt8](repeating: 0, count: 4_096)
    let count = read(reader, &buffer, buffer.count)
    guard count > 0 else { return false }
    lock.withLock {
      let room = Self.limitBytes + 1 - bytes.count
      if room > 0 { bytes.append(contentsOf: buffer.prefix(min(room, count))) }
    }
    return true
  }
}

/// SSH refusals that rerunning cannot fix: the server accepted no key, or ssh will not trust the
/// host key without asking. A background master can neither type a secret nor answer a prompt.
enum UserProductSSHRejection: Equatable, Sendable {
  case authRejected
  /// `staleEntry` holds the key ssh recorded for the host, which the server no longer presents.
  /// ssh names it for a changed key; for a key it never recorded there is none.
  case hostKeyRejected(staleEntry: UserProductKnownHostsEntry?)

  /// The refusal ssh's own messages report, if any.
  init?(sshMessages: Data) {
    switch sshMessages.withUnsafeBytes(ProductM2SSHFailureClassifier.classify) {
    case .authRejected: self = .authRejected
    case .hostKeyRejected:
      self = .hostKeyRejected(staleEntry: UserProductKnownHostsEntry(sshMessages: sshMessages))
    default: return nil
    }
  }

  /// The `powervpn run` failure token.
  var token: String {
    switch self {
    case .authRejected: "ssh_auth_rejected"
    case .hostKeyRejected: "ssh_host_key_rejected"
    }
  }

  func message(target: UserProductTarget) -> String {
    switch self {
    case .authRejected:
      "PowerVPN: \(target.key) rejected SSH public-key login; background SSH cannot type a password or passphrase."
    case .hostKeyRejected(staleEntry: .some):
      "PowerVPN: ssh does not trust the host key of \(target.key) (\(target.host)): it differs from the one known_hosts recorded."
    case .hostKeyRejected(staleEntry: nil):
      "PowerVPN: ssh does not trust the host key of \(target.key) (\(target.host)): it is not in known_hosts or has changed."
    }
  }

  func next(target: UserProductTarget) -> String {
    switch self {
    case .authRejected:
      "install your SSH public key on the server (README step 6, \"把 SSH 公钥装到服务器上\"); if it is already there, README \"出问题时\" covers ssh-agent and IdentitiesOnly"
    case .hostKeyRejected(let staleEntry?):
      "if the server really changed its host key, delete line \(staleEntry.line) of `\(staleEntry.file)`, which holds the old one, then run `powervpn ssh \(target.key) -- true` and accept the new key after checking its fingerprint (with StrictHostKeyChecking yes, add the verified key to that file yourself)"
    case .hostKeyRejected(staleEntry: nil):
      "run `powervpn ssh \(target.key) -- true` and act on what ssh reports: accept a new key after checking its fingerprint (with StrictHostKeyChecking yes, add the verified key to known_hosts yourself); if it reports nothing, `LogLevel QUIET` in ~/.ssh/config hides why, so set `LogLevel ERROR` for this host while you fix it"
    }
  }
}

/// A known_hosts line, as ssh names the one holding a host key the server no longer presents:
/// `Offending ED25519 key in /Users/me/.ssh/known_hosts:3`. It is the real file, whatever
/// UserKnownHostsFile or HostKeyAlias say, so `next:` can name it.
struct UserProductKnownHostsEntry: Equatable, Sendable {
  let file: String
  let line: Int

  init(file: String, line: Int) {
    self.file = file
    self.line = line
  }

  /// The first entry ssh's messages name; nil when they name none, or one whose path would put
  /// control characters on the terminal.
  init?(sshMessages: Data) {
    let prefix = Array("Offending ".utf8)
    let keyIn = Array(" key in ".utf8)
    for message in sshMessages.split(separator: UInt8(ascii: "\n")) {
      var message = Array(message)
      if message.last == UInt8(ascii: "\r") { message.removeLast() }
      // "Offending <type> key in FILE:LINE"; not "Offending key for IP in", which is no refusal.
      guard message.starts(with: prefix),
        let typeEnd = message[prefix.count...].firstIndex(of: UInt8(ascii: " ")),
        message[typeEnd...].starts(with: keyIn),
        let colon = message.lastIndex(of: UInt8(ascii: ":")),
        colon > typeEnd + keyIn.count,
        let line = Int(String(decoding: message[(colon + 1)...], as: UTF8.self)), line > 0
      else { continue }
      let path = Self.unescaped(message[(typeEnd + keyIn.count)..<colon])
      guard !path.contains(where: { $0 < 0x20 || $0 == 0x7f }) else { return nil }
      self.init(file: String(decoding: path, as: UTF8.self), line: line)
      return
    }
    return nil
  }

  /// Undoes the escapes ssh's log applies to a message (strnvis with VIS_SAFE | VIS_OCTAL): a
  /// byte outside printable ASCII may be `\ooo`, and a backslash is `\\`.
  private static func unescaped(_ bytes: ArraySlice<UInt8>) -> [UInt8] {
    let backslash = UInt8(ascii: "\\")
    let octalDigits = UInt8(ascii: "0")...UInt8(ascii: "7")
    var result: [UInt8] = []
    var index = bytes.startIndex
    while index < bytes.endIndex {
      let escape = bytes[(index + 1)...].prefix(3)
      if bytes[index] == backslash, escape.count == 3, escape.allSatisfy(octalDigits.contains) {
        result.append(
          UInt8(truncatingIfNeeded: escape.reduce(0) { $0 * 8 + Int($1 - UInt8(ascii: "0")) }))
        index += 4
      } else if bytes[index] == backslash, escape.first == backslash {
        result.append(backslash)
        index += 2
      } else {
        result.append(bytes[index])
        index += 1
      }
    }
    return result
  }
}
