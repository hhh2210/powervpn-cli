import Foundation
import PowerVPNCore

@main
struct PowerVPNCommand {
  static func main() async {
    do {
      try await run(Array(CommandLine.arguments.dropFirst()))
    } catch {
      FileHandle.standardError.write(Data("error: \(error)\n".utf8))
      Foundation.exit(1)
    }
  }

  private static func run(_ arguments: [String]) async throws {
    let command = arguments.first ?? "status"
    let json = arguments.contains("--json")

    switch command {
    case "status":
      renderStatus(SystemInspector().status(), json: json)
    case "probe":
      let timeout = timeoutValue(arguments) ?? 5
      let results = await probeAll(timeout: timeout)
      renderProbe(results, json: json)
      if results.contains(where: { $0.status != .healthy }) {
        Foundation.exit(2)
      }
    case "diagnose":
      renderStatus(SystemInspector().status(), json: json)
      let results = await probeAll(timeout: timeoutValue(arguments) ?? 5)
      renderProbe(results, json: json)
      if results.contains(where: { $0.status != .healthy }) {
        Foundation.exit(2)
      }
    case "reconnect":
      guard arguments.contains("--yes") else {
        throw CLIError.confirmationRequired
      }
      try await PowerVPNController().reconnect()
      print(
        "PowerVPN was terminated and relaunched. Authentication remains under PowerVPN control.")
    case "help", "--help", "-h":
      printUsage()
    default:
      throw CLIError.unknownCommand(command)
    }
  }

  private static func probeAll(timeout: TimeInterval) async -> [ProbeResult] {
    await withTaskGroup(of: ProbeResult.self) { group in
      let probe = SSHBannerProbe()
      for target in VPNTarget.defaults {
        group.addTask { await probe.probe(target: target, timeout: timeout) }
      }
      var results: [ProbeResult] = []
      for await result in group { results.append(result) }
      return results.sorted { $0.target.name < $1.target.name }
    }
  }

  private static func renderStatus(_ status: PowerVPNStatus, json: Bool) {
    if json {
      printJSON(status)
      return
    }
    print("PowerVPN \(status.appVersion ?? "unknown") (\(status.appBuild ?? "unknown"))")
    print(
      "app: \(status.appRunning ? "running" : "stopped") [\(status.appArchitectures.joined(separator: ", "))]"
    )
    print(
      "helper: \(status.helper.state ?? "unknown") pid=\(status.helper.pid.map(String.init) ?? "-") crashes=\(status.helper.successiveCrashes.map(String.init) ?? "-")"
    )
    if let signal = status.helper.lastTerminatingSignal {
      print("helper last signal: \(signal)")
    }
    print("tunnel: \(status.tunnel.health.rawValue) (\(status.tunnel.latestEvent))")
  }

  private static func renderProbe(_ results: [ProbeResult], json: Bool) {
    if json {
      printJSON(results)
      return
    }
    for result in results {
      print(
        "\(result.target.name): \(result.status.rawValue) \(result.latencyMilliseconds)ms — \(result.detail)"
      )
    }
  }

  private static func printJSON<T: Encodable>(_ value: T) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(value) {
      print(String(decoding: data, as: UTF8.self))
    }
  }

  private static func timeoutValue(_ arguments: [String]) -> TimeInterval? {
    guard let index = arguments.firstIndex(of: "--timeout"),
      arguments.indices.contains(index + 1)
    else { return nil }
    return TimeInterval(arguments[index + 1])
  }

  private static func printUsage() {
    print(
      """
      Usage: powervpn <command> [options]

        status                 Show GUI, helper, crash, and tunnel state
        probe [--timeout N]    Read SSH banners from thu21 and thu52
        diagnose              Run status and probe together
        reconnect --yes       Explicitly terminate and relaunch PowerVPN

      Options:
        --json                 Emit JSON
      """)
  }
}

private enum CLIError: Error, CustomStringConvertible {
  case unknownCommand(String)
  case confirmationRequired

  var description: String {
    switch self {
    case .unknownCommand(let command):
      return "unknown command: \(command)"
    case .confirmationRequired:
      return "reconnect changes the active VPN session; rerun with --yes"
    }
  }
}
