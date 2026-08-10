import Foundation
import PowerVPNCore
import PowerVPNPortal
import PowerVPNProduct

@main
struct PowerVPNCommand {
  static func main() async {
    do {
      try await run(Array(CommandLine.arguments.dropFirst()))
    } catch let error as ProductCommandError {
      FileHandle.standardError.write(Data("error: \(error)\n".utf8))
      Foundation.exit(64)
    } catch {
      FileHandle.standardError.write(Data("error: \(error)\n".utf8))
      Foundation.exit(1)
    }
  }

  private static func run(_ arguments: [String]) async throws {
    let command = arguments.first ?? "status"
    let json = arguments.contains("--json")

    switch command {
    case "doctor", "helper", "resources", "snapshot":
      let result = try runProductCommand(arguments)
      print(result.standardOutput)
      if result.exitCode != 0 {
        Foundation.exit(result.exitCode)
      }
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
    case "oracle":
      try runOracle(arguments, json: json)
    case "spec":
      try runSpec(arguments, json: json)
    case "vici":
      try runVICICommand(arguments, json: json)
    case "xpc":
      try await runVendorXPCCommand(arguments, json: json)
    case "login":
      let result = try await runPortalLoginCommand(arguments)
      print(result.standardOutput)
      if result.exitCode != 0 {
        Foundation.exit(result.exitCode)
      }
    case "help", "--help", "-h":
      printUsage()
    default:
      throw CLIError.unknownCommand(command)
    }
  }

  private static func runOracle(_ arguments: [String], json: Bool) throws {
    let subcommand = arguments.dropFirst().first { !$0.hasPrefix("--") } ?? "inventory"
    if subcommand == "inventory" {
      renderOracle(SystemInspector().oracleInventory(), json: json)
      return
    }
    if subcommand == "correlate" {
      guard let subcommandIndex = arguments.firstIndex(of: subcommand),
        arguments.indices.contains(subcommandIndex + 1),
        !arguments[subcommandIndex + 1].hasPrefix("--")
      else {
        throw CLIError.invalidArguments(
          "usage: powervpn oracle correlate <value-free-trace.json> [--json]"
        )
      }
      renderCorrelationValidation(
        try ProtocolCorrelationRedactedValidator.validate(
          contentsOf: URL(fileURLWithPath: arguments[subcommandIndex + 1])
        ),
        json: json
      )
      return
    }
    throw CLIError.unknownSubcommand(command: "oracle", subcommand: subcommand)
  }

  private static func renderCorrelationValidation(
    _ report: ProtocolCorrelationValidationReport,
    json: Bool
  ) {
    if json {
      printJSON(report)
    } else if report.valid {
      print("valid value-free protocol correlation fixture")
    } else {
      print("invalid value-free protocol correlation fixture")
      for issue in report.issues {
        print("  \(issue.path): \(issue.message) [\(issue.code)]")
      }
    }
    if !report.valid {
      Foundation.exit(2)
    }
  }

  private static func runSpec(_ arguments: [String], json: Bool) throws {
    guard arguments.count >= 3 else {
      throw CLIError.invalidArguments(
        "usage: powervpn spec <validate-redacted|vici-dry-run> <path> [--json]"
      )
    }
    let url = URL(fileURLWithPath: arguments[2])
    switch arguments[1] {
    case "validate-redacted":
      let report = try TunnelSpecRedactedValidator.validate(contentsOf: url)
      if json {
        printJSON(report)
      } else if report.valid {
        print("valid redacted TunnelSpec fixture")
      } else {
        print("invalid redacted TunnelSpec fixture")
        for issue in report.issues {
          print("  \(issue.path): \(issue.message) [\(issue.code)]")
        }
      }
      if !report.valid {
        Foundation.exit(2)
      }
    case "vici-dry-run":
      let report = try TunnelSpecVICIDryRun.build(contentsOf: url).report
      if json {
        printJSON(report)
      } else {
        print("VICI load-conn dry run: \(report.payloadByteCount) bytes")
        print("sha256: \(report.payloadSHA256)")
        print("side effects: none")
      }
    default:
      throw CLIError.unknownSubcommand(command: "spec", subcommand: arguments[1])
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
    let tunnelLabel = status.tunnel.historicalHint ? "historical tunnel hint" : "tunnel"
    print("\(tunnelLabel): \(status.tunnel.health.rawValue) (\(status.tunnel.latestEvent))")
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

  private static func renderOracle(_ inventory: VendorHelperInventory, json: Bool) {
    if json {
      printJSON(inventory)
      return
    }
    print("PowerVPN \(inventory.vendor.version) build \(inventory.vendor.build)")
    print(
      "strongSwan upstream base: \(inventory.upstreamStrongSwanVersion.value) (\(inventory.upstreamStrongSwanVersion.evidence)); vendor patch level: \(inventory.vendorPatchLevel)"
    )
    for helper in inventory.helpers {
      print(
        "helper: \(helper.path) [\(helper.architectures.joined(separator: ", "))] sha256=\(helper.sha256) build=\(helper.vendorBuild)"
      )
    }
    print("loaded plugins: \(inventory.loadedPlugins.joined(separator: ", "))")
    renderEvidence("strongSwan", inventory.staticEvidence.strongSwan)
    renderEvidence("leadsecbridge", inventory.staticEvidence.leadsecbridge)
    renderEvidence("kernel-libipsec", inventory.staticEvidence.kernelLibIPSec)
    renderEvidence("kernel-osx", inventory.staticEvidence.kernelOSX)
    renderEvidence("XAuth static binary capability", inventory.staticEvidence.xAuth)
    renderEvidence("Mode Config static binary capability", inventory.staticEvidence.modeConfig)
    renderEvidence("VICI", inventory.staticEvidence.vici)
    print(
      "leadsecbridge classification: configuration adapter=\(inventory.leadsecbridgeClassification.configurationAdapter.rawValue), custom strongSwan plugin=\(inventory.leadsecbridgeClassification.customStrongSwanPlugin.rawValue), private IKEv1 resource-rule extension=\(inventory.leadsecbridgeClassification.privateIKEv1ResourceRuleExtension.rawValue)"
    )
  }

  private static func renderEvidence(_ name: String, _ evidence: OracleEvidenceMarker) {
    let state = evidence.observed ? "observed" : "not observed"
    let markers = evidence.markers.isEmpty ? "-" : evidence.markers.joined(separator: ", ")
    print("evidence \(name): \(state) [\(markers)]")
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
        oracle [inventory]     Read-only vendor helper and protocol inventory
        oracle correlate <value-free-trace.json>
                               Validate metadata-only control/XPC correlation
        spec validate-redacted <path>
                               Validate a commit-safe redacted TunnelSpec fixture
        spec vici-dry-run <path>
                               Build and hash a pure-Swift VICI load-conn payload
        vici version --socket <path> [--timeout-ms N]
                               Run a value-free version request against charon
        vici cp7a-smoke --socket <path> [--timeout-ms N]
                               Run bounded synthetic load/list/unload over VICI
        xpc get-version [--timeout-ms N]
                               Read the installed charon helper version over exact XPC
        login                  Run the sealed username/password portal transaction
        doctor --json          Show product readiness and the first blocker
        helper status --json   Show helper generation and direct-XPC probe state
        resources --json       List selectable authorized resources, if available
        snapshot --dry-run --json
                               Check vendor snapshot completeness without serializing it

      Options:
        --json                 Emit JSON
      """)
  }
}

private enum CLIError: Error, CustomStringConvertible {
  case unknownCommand(String)
  case unknownSubcommand(command: String, subcommand: String)
  case invalidArguments(String)

  var description: String {
    switch self {
    case .unknownCommand(let command):
      return "unknown command: \(command)"
    case .unknownSubcommand(let command, let subcommand):
      return "unknown \(command) subcommand: \(subcommand)"
    case .invalidArguments(let usage):
      return usage
    }
  }
}
