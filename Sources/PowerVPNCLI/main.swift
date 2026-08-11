import Foundation
import PowerVPNCore
import PowerVPNPortal
import PowerVPNProduct

@main
struct PowerVPNCommand {
  static func main() async {
    do {
      try await run(Array(CommandLine.arguments.dropFirst()))
    } catch let error as M2ConnectOnceCommandError {
      FileHandle.standardError.write(Data("error: \(error)\n".utf8))
      Foundation.exit(64)
    } catch let error as LegacyNetworkCommandError {
      FileHandle.standardError.write(Data("error: \(error)\n".utf8))
      Foundation.exit(64)
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
      let result = try await runProductCommand(arguments)
      print(result.standardOutput)
      if result.exitCode != 0 {
        Foundation.exit(result.exitCode)
      }
    case "status":
      renderStatus(SystemInspector().status(), json: json)
    case "probe", "diagnose":
      let result = try runLegacyNetworkCommand(arguments)
      print(result.standardOutput)
      Foundation.exit(result.exitCode)
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
    case "m2":
      let runtime = ProductM2CurrentMachineRuntime()
      let result = try await runM2ConnectOnceCommand(
        arguments,
        authorizationAvailabilityFailure: {
          runtime.authorizationAvailabilityFailure
        },
        runtime: { request, budget in
          await runtime.run(request, budget: budget)
        }
      )
      print(result.standardOutput)
      if result.exitCode != 0 {
        Foundation.exit(result.exitCode)
      }
    case "help", "--help", "-h":
      printCLIUsage()
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
