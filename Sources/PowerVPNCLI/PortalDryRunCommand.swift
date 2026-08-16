import Foundation
import PowerVPNPortal
import PowerVPNProduct

enum PortalDryRunCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments
  case configuration(String)

  var description: String {
    switch self {
    case .invalidArguments:
      return
        "usage: powervpn portal dry-run --resource-display-name <exact> --ssh-target <key> --json"
    case .configuration(let token):
      return token
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

func runCurrentMachinePortalDryRunCommand(
  _ arguments: [String],
  loadConfiguration: @escaping @Sendable () throws -> PowerVPNTargetsConfiguration = {
    try PowerVPNTargetsConfiguration.currentMachine()
  }
) async throws -> PortalDryRunCommandResult {
  let unresolved = try parsePortalDryRunArguments(arguments)
  let configuration: PowerVPNTargetsConfiguration
  do {
    configuration = try loadConfiguration()
  } catch let error as PowerVPNTargetsConfigurationError {
    throw PortalDryRunCommandError.configuration(error.token)
  }
  do {
    _ = try ProductM2SSHTarget(
      key: unresolved.sshTarget.rawValue,
      configuration: configuration
    )
  } catch let error as PowerVPNTargetsConfigurationError {
    throw PortalDryRunCommandError.configuration(error.token)
  }
  let runtime = ProductPortalDryRunRuntime(configuration: configuration)
  return try await runPortalDryRunCommand(
    arguments,
    resolveTarget: { key in
      try ProductM2SSHTarget(key: key, configuration: configuration)
    },
    runtime: { request in await runtime.run(request) }
  )
}

func runPortalDryRunCommand(
  _ arguments: [String],
  resolveTarget: @escaping @Sendable (String) throws -> ProductM2SSHTarget = {
    guard let target = ProductM2SSHTarget(rawValue: $0) else {
      throw PortalDryRunCommandError.invalidArguments
    }
    return target
  },
  runtime: @escaping PortalDryRunRuntimeOperation = { request in
    await ProductPortalDryRunRuntime().run(request)
  },
  signalMonitorFactory: CLISignalMonitorFactory = { DarwinCLISignalMonitor() }
) async throws -> PortalDryRunCommandResult {
  let request = try parsePortalDryRunArguments(arguments, resolveTarget: resolveTarget)
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
  _ arguments: [String],
  resolveTarget: (String) throws -> ProductM2SSHTarget = {
    guard let target = ProductM2SSHTarget(rawValue: $0) else {
      throw PortalDryRunCommandError.invalidArguments
    }
    return target
  }
) throws -> ProductPortalDryRunRequest {
  guard arguments.count == 7,
    arguments[0] == "portal",
    arguments[1] == "dry-run",
    arguments[2] == "--resource-display-name",
    arguments[4] == "--ssh-target",
    arguments[6] == "--json",
    validResourceDisplayName(arguments[3])
  else { throw PortalDryRunCommandError.invalidArguments }

  let target = try resolveTarget(arguments[5])
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
