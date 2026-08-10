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
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
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
  public static let allowlistedMarkers = [established, retryMarker] + staleMarkers

  public static func analyze(_ text: String) -> TunnelLogState {
    let establishedIndex = text.range(of: established, options: .backwards)?.lowerBound
    let staleIndex = staleMarkers.compactMap {
      text.range(of: $0, options: .backwards)?.lowerBound
    }.max()
    let retryIndex = text.range(of: retryMarker, options: .backwards)?.lowerBound

    if let establishedIndex, staleIndex.map({ establishedIndex > $0 }) ?? true {
      return TunnelLogState(
        health: .healthy,
        latestEvent: "historical log hint: CHILD_SA established"
      )
    }
    if let staleIndex, establishedIndex.map({ staleIndex > $0 }) ?? true {
      return TunnelLogState(
        health: .staleAuthentication,
        latestEvent:
          "historical log hint: IKE authentication failed after the last established tunnel"
      )
    }
    if let retryIndex, establishedIndex.map({ retryIndex > $0 }) ?? true {
      return TunnelLogState(
        health: .retrying,
        latestEvent: "historical log hint: IKE retransmission observed"
      )
    }
    return TunnelLogState(
      health: .unknown,
      latestEvent: "historical log hint: no decisive tunnel event"
    )
  }
}

public enum TunnelStateResolver {
  public static func resolve(
    helper: HelperState,
    analyzedLogState: TunnelLogState
  ) -> TunnelLogState {
    guard helper.isRunning else {
      return TunnelLogState(
        health: .stopped,
        latestEvent: "helper not running; historical tunnel log ignored",
        historicalHint: false
      )
    }
    return TunnelLogState(
      health: .unknown,
      latestEvent: "\(analyzedLogState.latestEvent); current helper generation is uncorrelated",
      historicalHint: true
    )
  }
}

public struct SystemInspector: Sendable {
  public static let appPath = "/Applications/PowerVPN.app"
  public static let helperLabel = "system/com.leadsec.charon-xpc"
  public static let logPath = "/var/log/vsgvpn.log"

  let runner: CommandRunner

  public init(runner: CommandRunner = CommandRunner()) {
    self.runner = runner
  }

  public func installation() -> PowerVPNInstallation {
    let appURL = URL(fileURLWithPath: Self.appPath)
    let bundle = Bundle(url: appURL)
    return PowerVPNInstallation(
      appVersion: bundle?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
      appBuild: bundle?.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
      appArchitectures: architectures(of: "\(Self.appPath)/Contents/MacOS/PowerVPN"),
      appRunning: !NSRunningApplication.runningApplications(
        withBundleIdentifier: "com.leadsec.PowerVPN-Mac"
      ).isEmpty
    )
  }

  public func status() -> PowerVPNStatus {
    let installation = installation()
    let helperOutput = (try? runner.run("/bin/launchctl", ["print", Self.helperLabel])) ?? ""
    let helper = HelperOutputParser.parse(helperOutput)
    let log = AllowlistedLogReader.readLines(
      path: Self.logPath,
      maximumBytes: 256 * 1_024,
      markers: TunnelLogAnalyzer.allowlistedMarkers
    )
    let tunnel = TunnelStateResolver.resolve(
      helper: helper,
      analyzedLogState: TunnelLogAnalyzer.analyze(log)
    )
    return PowerVPNStatus(
      appVersion: installation.appVersion,
      appBuild: installation.appBuild,
      appArchitectures: installation.appArchitectures,
      appRunning: installation.appRunning,
      helper: helper,
      tunnel: tunnel
    )
  }

  func architectures(of path: String) -> [String] {
    guard let output = try? runner.run("/usr/bin/file", [path]) else { return [] }
    return ["arm64", "x86_64"].filter { output.contains($0) }
  }
}
