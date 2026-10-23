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
  /// The first `UserKnownHostsFile`, where ssh records an accepted host key. `ssh -G` prints the
  /// list unquoted, so a path containing a space is cut at the space.
  var knownHostsFile: String? = nil
  /// The name host keys are recorded under instead of `hostname`.
  var hostKeyAlias: String? = nil

  static func parse(_ output: String) -> Self? {
    var values: [String: String] = [:]
    for line in output.split(separator: "\n") {
      let parts = line.split(separator: " ", maxSplits: 1)
      guard parts.count == 2 else { continue }
      let key = String(parts[0])
      if [
        "hostname", "user", "port", "controlmaster", "controlpath", "userknownhostsfile",
        "hostkeyalias",
      ].contains(key) {
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
      controlPath: controlPath,
      knownHostsFile: values["userknownhostsfile"]?.split(separator: " ").first.map(String.init),
      hostKeyAlias: values["hostkeyalias"]
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
  /// would bury it past the read limit and keep the backgrounded master writing for the whole
  /// session. Without a log they are discarded.
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

/// A private file for ssh's own messages (`ssh -E`) while it starts a master.
///
/// The master's stderr cannot be captured instead: ssh hands it to the ProxyCommand, which keeps
/// it open for the whole session. The messages can name the user and host, so they are only
/// classified, never printed. The file lives in the session state directory, is emptied and
/// removed as soon as the start is decided, and a start that was killed first leaves it for the
/// next `up` to remove.
struct UserProductSSHDiagnosticLog: Sendable {
  static let limitBytes = 16 * 1_024
  private static let namePrefix = "ssh-master-"
  private static let nameSuffix = ".log"

  let path: String

  /// nil when the file cannot be created; the master then starts with its messages discarded.
  static func create(directory: String) -> Self? {
    var template = Array(
      (directory as NSString)
        .appendingPathComponent(namePrefix + "XXXXXX" + nameSuffix).utf8CString)
    let descriptor = mkstemps(&template, Int32(nameSuffix.utf8.count))
    guard descriptor >= 0 else { return nil }
    close(descriptor)
    return Self(path: String(cString: template))
  }

  /// Removes the logs of starts that were killed before they removed their own. Only `up` creates
  /// these files, and it holds the session command lock, so none of them is still being decided.
  static func removeLeftovers(directory: String) {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
    for name in names where name.hasPrefix(namePrefix) && name.hasSuffix(nameSuffix) {
      Self(path: (directory as NSString).appendingPathComponent(name)).remove()
    }
  }

  /// The SSH failure the messages name; nil when they are unreadable, over `limitBytes`, or name
  /// nothing the classifier knows.
  func failureClass() -> ProductM2SSHFailureClass? {
    let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard descriptor >= 0 else { return nil }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      metadata.st_uid == getuid(),
      metadata.st_mode & S_IFMT == S_IFREG,
      var bytes = try? handle.read(upToCount: Self.limitBytes + 1),
      bytes.count <= Self.limitBytes
    else { return nil }
    defer { bytes.resetBytes(in: bytes.indices) }
    return bytes.withUnsafeBytes(ProductM2SSHFailureClassifier.classify)
  }

  /// Empties the file before unlinking it: a master that started keeps its descriptor (and so
  /// does its ProxyCommand), so unlinking alone would leave the startup messages on disk.
  func remove() {
    let descriptor = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    if descriptor >= 0 {
      var metadata = stat()
      if fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG {
        ftruncate(descriptor, 0)
      }
      close(descriptor)
    }
    unlink(path)
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

  /// The host-key step names the known_hosts file and lookup name ssh actually uses.
  func next(
    target: UserProductTarget,
    configuration: UserProductSSHEffectiveConfiguration
  ) -> String {
    switch self {
    case .authRejected:
      "install your SSH public key on the server (README step 6, \"把 SSH 公钥装到服务器上\"); if it is already there, README \"出问题时\" covers ssh-agent and IdentitiesOnly"
    case .hostKeyRejected:
      hostKeyNext(
        target: target,
        file: configuration.knownHostsFile ?? "~/.ssh/known_hosts",
        name: configuration.hostKeyAlias ?? target.host)
    }
  }

  private func hostKeyNext(target: UserProductTarget, file: String, name: String) -> String {
    let file = shellWord(file)
    return
      "verify the server's host key and record it in \(file): if it really changed, `ssh-keygen -f \(file) -R \(shellWord(name))` first; then `powervpn ssh \(target.key) -- true` and accept it (with StrictHostKeyChecking yes, add it to that file yourself)"
  }

  private func shellWord(_ value: String) -> String {
    let plain = value.unicodeScalars.allSatisfy {
      CharacterSet.alphanumerics.contains($0) || "/._~-".unicodeScalars.contains($0)
    }
    return plain ? value : "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}
