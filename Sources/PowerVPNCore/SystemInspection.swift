import AppKit
import Foundation
import MachO

public enum CommandError: Error, CustomStringConvertible {
  case failed(executable: String, status: Int32, output: String)

  public var description: String {
    switch self {
    case .failed(let executable, let status, let output):
      return "\(executable) exited with \(status): \(output)"
    }
  }
}

public struct CommandRunner: Sendable {
  public init() {}

  public func run(_ executable: String, _ arguments: [String]) throws -> String {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()
    process.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(decoding: data, as: UTF8.self)
    guard process.terminationStatus == 0 else {
      throw CommandError.failed(
        executable: executable,
        status: process.terminationStatus,
        output: output
      )
    }
    return output
  }
}

public enum HelperOutputParser {
  public static func parse(_ output: String) -> HelperState {
    HelperState(
      state: capture(#"(?m)^\s*state = ([^\n]+)$"#, in: output),
      pid: captureInt(#"(?m)^\s*pid = (\d+)$"#, in: output),
      runs: captureInt(#"(?m)^\s*runs = (\d+)$"#, in: output),
      successiveCrashes: captureInt(#"(?m)^\s*successive crashes = (\d+)$"#, in: output),
      lastTerminatingSignal: capture(
        #"(?m)^\s*last terminating signal = ([^\n]+)$"#,
        in: output
      )
    )
  }

  private static func capture(_ pattern: String, in text: String) -> String? {
    guard let regex = try? NSRegularExpression(pattern: pattern),
      let match = regex.firstMatch(
        in: text,
        range: NSRange(text.startIndex..., in: text)
      ),
      let range = Range(match.range(at: 1), in: text)
    else { return nil }
    return String(text[range]).trimmingCharacters(in: .whitespaces)
  }

  private static func captureInt(_ pattern: String, in text: String) -> Int? {
    capture(pattern, in: text).flatMap(Int.init)
  }
}

public enum TunnelLogAnalyzer {
  private static let established = "CHILD_SA"
  private static let staleMarkers = [
    "invalid HASH_V1 payload length",
    "giving up after 5 retransmits",
  ]
  private static let retryMarker = "sending retransmit"

  public static func analyze(_ text: String) -> TunnelLogState {
    let establishedIndex = text.range(of: established, options: .backwards)?.lowerBound
    let staleIndex = staleMarkers.compactMap {
      text.range(of: $0, options: .backwards)?.lowerBound
    }.max()
    let retryIndex = text.range(of: retryMarker, options: .backwards)?.lowerBound

    if let establishedIndex, staleIndex.map({ establishedIndex > $0 }) ?? true {
      return TunnelLogState(health: .healthy, latestEvent: "CHILD_SA established")
    }
    if let staleIndex, establishedIndex.map({ staleIndex > $0 }) ?? true {
      return TunnelLogState(
        health: .staleAuthentication,
        latestEvent: "IKE authentication failed after the last established tunnel"
      )
    }
    if let retryIndex, establishedIndex.map({ retryIndex > $0 }) ?? true {
      return TunnelLogState(health: .retrying, latestEvent: "IKE retransmission in progress")
    }
    return TunnelLogState(health: .unknown, latestEvent: "no decisive tunnel event")
  }
}

public struct SystemInspector: Sendable {
  public static let appPath = "/Applications/PowerVPN.app"
  public static let helperLabel = "system/com.leadsec.charon-xpc"
  public static let logPath = "/var/log/vsgvpn.log"

  private let runner = CommandRunner()

  public init() {}

  public func status() -> PowerVPNStatus {
    let appURL = URL(fileURLWithPath: Self.appPath)
    let bundle = Bundle(url: appURL)
    let helperOutput = (try? runner.run("/bin/launchctl", ["print", Self.helperLabel])) ?? ""
    let helper = HelperOutputParser.parse(helperOutput)
    let log = readTail(path: Self.logPath, maximumBytes: 256 * 1_024)
    let tunnel = TunnelLogAnalyzer.analyze(log)
    let running = !NSRunningApplication.runningApplications(
      withBundleIdentifier: "com.leadsec.PowerVPN-Mac"
    ).isEmpty

    return PowerVPNStatus(
      appVersion: bundle?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
      appBuild: bundle?.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
      appArchitectures: architectures(of: "\(Self.appPath)/Contents/MacOS/PowerVPN"),
      appRunning: running,
      helper: helper,
      tunnel: tunnel
    )
  }

  private func readTail(path: String, maximumBytes: UInt64) -> String {
    guard let handle = FileHandle(forReadingAtPath: path) else { return "" }
    defer { try? handle.close() }
    let end = (try? handle.seekToEnd()) ?? 0
    let start = end > maximumBytes ? end - maximumBytes : 0
    try? handle.seek(toOffset: start)
    return String(decoding: (try? handle.readToEnd()) ?? Data(), as: UTF8.self)
  }

  private func architectures(of path: String) -> [String] {
    guard let output = try? runner.run("/usr/bin/file", [path]) else { return [] }
    return ["arm64", "x86_64"].filter { output.contains($0) }
  }
}

@MainActor
public struct PowerVPNController {
  public init() {}

  public func reconnect() async throws {
    let running = NSRunningApplication.runningApplications(
      withBundleIdentifier: "com.leadsec.PowerVPN-Mac"
    )
    for app in running {
      _ = app.terminate()
    }

    let deadline = ContinuousClock.now + .seconds(8)
    while ContinuousClock.now < deadline {
      let remaining = NSRunningApplication.runningApplications(
        withBundleIdentifier: "com.leadsec.PowerVPN-Mac"
      )
      if remaining.isEmpty { break }
      try await Task.sleep(for: .milliseconds(200))
    }

    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = false
    _ = try await NSWorkspace.shared.openApplication(
      at: URL(fileURLWithPath: SystemInspector.appPath),
      configuration: configuration
    )
  }
}
