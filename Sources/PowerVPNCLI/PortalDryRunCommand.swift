import Foundation
import PowerVPNProduct

enum PortalDryRunCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String {
    switch self {
    case .invalidArguments:
      return
        "usage: powervpn portal dry-run --resource-display-name <exact> --ssh-target <thu21|thu52> --json"
    }
  }
}

struct PortalDryRunCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

typealias PortalDryRunRuntimeOperation =
  @Sendable (
    ProductPortalDryRunRequest
  ) async -> ProductPortalDryRunReport

func runPortalDryRunCommand(
  _ arguments: [String],
  runtime: @escaping PortalDryRunRuntimeOperation = { request in
    await ProductPortalDryRunRuntime().run(request)
  },
  signalMonitorFactory: CLISignalMonitorFactory = { DarwinCLISignalMonitor() }
) async throws -> PortalDryRunCommandResult {
  let request = try parsePortalDryRunArguments(arguments)
  let cancellation = CLITaskCancellation<ProductPortalDryRunReport>()
  let monitor = signalMonitorFactory()
  monitor.start { cancellation.request() }
  defer {
    cancellation.clear()
    monitor.stop()
  }

  let task = Task { await runtime(request) }
  cancellation.install(task)
  let report = await task.value
  return PortalDryRunCommandResult(
    standardOutput: try portalDryRunJSON(report),
    exitCode: portalDryRunExitCode(report)
  )
}
func parsePortalDryRunArguments(
  _ arguments: [String]
) throws -> ProductPortalDryRunRequest {
  guard arguments.count == 7,
    arguments[0] == "portal",
    arguments[1] == "dry-run",
    arguments[2] == "--resource-display-name",
    arguments[4] == "--ssh-target",
    arguments[6] == "--json",
    validResourceDisplayName(arguments[3])
  else { throw PortalDryRunCommandError.invalidArguments }

  let target: ProductM2SSHTarget
  switch arguments[5] {
  case "thu21": target = .thu21
  case "thu52": target = .thu52
  default: throw PortalDryRunCommandError.invalidArguments
  }
  return ProductPortalDryRunRequest(
    resourceDisplayName: arguments[3],
    sshTarget: target
  )
}

func portalDryRunExitCode(_ report: ProductPortalDryRunReport) -> Int32 {
  if report.dryRunAccepted { return 0 }
  if report.outcome == .cancelled { return 130 }
  return 69
}

private func portalDryRunJSON(_ report: ProductPortalDryRunReport) throws -> String {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys]
  let data = try encoder.encode(report)
  guard let output = String(data: data, encoding: .utf8) else {
    throw PortalDryRunCommandError.invalidArguments
  }
  return output
}
