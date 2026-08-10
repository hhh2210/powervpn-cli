import Foundation
import PowerVPNProduct

enum M2ConnectOnceCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String {
    "usage: powervpn m2 connect-once --resource-display-name <exact> --ssh-target <thu21|thu52> --json"
  }
}

struct M2ConnectOnceCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

typealias M2ConnectOnceRuntimeOperation =
  @Sendable (ProductM2ConnectRequest) async -> ProductM2ConnectReport

func runM2ConnectOnceCommand(
  _ arguments: [String],
  generateApprovalCode: @escaping @Sendable () throws -> String = M2TTYApproval.secureCode,
  approval: M2TTYApproval = M2TTYApproval(),
  signalMonitorFactory: CLISignalMonitorFactory = { DarwinCLISignalMonitor() },
  runtime: @escaping M2ConnectOnceRuntimeOperation = { request in
    await ProductM2CurrentMachineRuntime().run(request)
  }
) async throws -> M2ConnectOnceCommandResult {
  let request = try parseM2ConnectOnceArguments(arguments)
  let code: String
  do {
    code = try generateApprovalCode()
  } catch {
    return try approvalResult(.unavailable)
  }
  let approvalOutcome = approval.request(
    code: code,
    resourceDisplayName: request.resourceDisplayName,
    sshTarget: request.sshTarget.rawValue
  )
  guard approvalOutcome == .accepted else {
    return try approvalResult(approvalOutcome)
  }

  let cancellation = CLITaskCancellation<M2RuntimeExecution>()
  let monitor = signalMonitorFactory()
  monitor.start { cancellation.request() }
  defer {
    cancellation.clear()
    monitor.stop()
  }
  let gate = CLITaskStartGate()
  let task = Task {
    await gate.wait()
    guard !Task.isCancelled else { return M2RuntimeExecution.cancelledBeforeRuntime }
    return M2RuntimeExecution.report(await runtime(request))
  }
  cancellation.install(task)
  await gate.open()
  switch await task.value {
  case .cancelledBeforeRuntime:
    return try lifecycleResult("cancelled_before_mutation", exitCode: 130)
  case .report(let report):
    return try encodedResult(report, exitCode: m2ConnectOnceExitCode(report))
  }
}

func parseM2ConnectOnceArguments(
  _ arguments: [String]
) throws -> ProductM2ConnectRequest {
  guard arguments.count == 7,
    arguments[0] == "m2",
    arguments[1] == "connect-once",
    arguments[2] == "--resource-display-name",
    arguments[4] == "--ssh-target",
    arguments[6] == "--json"
  else { throw M2ConnectOnceCommandError.invalidArguments }
  let displayName = arguments[3]
  guard validResourceDisplayName(displayName) else {
    throw M2ConnectOnceCommandError.invalidArguments
  }
  let target: ProductM2SSHTarget
  switch arguments[5] {
  case "thu21": target = .thu21
  case "thu52": target = .thu52
  default: throw M2ConnectOnceCommandError.invalidArguments
  }
  return ProductM2ConnectRequest(resourceDisplayName: displayName, sshTarget: target)
}

func m2ConnectOnceExitCode(_ report: ProductM2ConnectReport) -> Int32 {
  if report.outcome == .cleanupUnproven { return 74 }
  if report.helperMutationRequested, !report.cleanupVerified { return 74 }
  if report.outcome == .connectedAndCleanedUp {
    return report.finalState == .disconnected && report.cleanupVerified ? 0 : 1
  }
  if report.outcome == .cancelled { return 130 }
  if !report.helperMutationRequested { return 69 }
  if report.cleanupVerified { return 70 }
  return 1
}

private func validResourceDisplayName(_ value: String) -> Bool {
  (1...256).contains(value.utf8.count)
    && !value.unicodeScalars.contains {
      CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0)
    }
}

private enum M2RuntimeExecution: Sendable {
  case cancelledBeforeRuntime
  case report(ProductM2ConnectReport)
}

private struct M2LifecycleCommandReport: Encodable {
  let schemaVersion = 1
  let outcome: String
  let runtimeInvoked: Bool
  let containsSecrets = false
}

private func approvalResult(
  _ outcome: M2TTYApprovalOutcome
) throws -> M2ConnectOnceCommandResult {
  try lifecycleResult(
    outcome == .denied ? "approval_denied" : "approval_unavailable",
    exitCode: 77
  )
}

private func lifecycleResult(
  _ outcome: String,
  exitCode: Int32
) throws -> M2ConnectOnceCommandResult {
  try encodedResult(
    M2LifecycleCommandReport(outcome: outcome, runtimeInvoked: false),
    exitCode: exitCode)
}

private func encodedResult<T: Encodable>(
  _ value: T,
  exitCode: Int32
) throws -> M2ConnectOnceCommandResult {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  return M2ConnectOnceCommandResult(
    standardOutput: String(decoding: try encoder.encode(value), as: UTF8.self),
    exitCode: exitCode
  )
}
