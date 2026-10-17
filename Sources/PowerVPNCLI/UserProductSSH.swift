import Darwin
import Foundation

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

  static func startMaster(
    target: String,
    controlPath: String,
    executablePath: String,
    sessionID: String
  ) -> [String] {
    [
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
