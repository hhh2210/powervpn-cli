import Foundation
import PowerVPNProduct

enum VendorOnceCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String { "usage: powervpn vendor-once handoff --json" }
}

private struct VendorOnceApprovalReport: Encodable, Sendable {
  let schemaVersion = 1
  let outcome: String
  let onboardingMode = "vendor_once"
  let productCoordinatorConstructed = false
  let containsSecrets = false
}

struct VendorOnceCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

typealias VendorOnceHandoffOperation =
  @Sendable (
    @escaping @Sendable () async -> VendorAppNonLogoutHandoffApproval
  ) async -> VendorAppNonLogoutHandoffReport

func runVendorOnceCommand(
  _ arguments: [String],
  generateApprovalCode: @escaping @Sendable () throws -> String = M2TTYApproval.secureCode,
  approval: M2TTYApproval = M2TTYApproval(),
  signalMonitorFactory: CLISignalMonitorFactory = { DarwinCLISignalMonitor() },
  handoff: @escaping VendorOnceHandoffOperation = { secondApproval in
    await VendorAppNonLogoutHandoffCoordinator().run(secondApproval: secondApproval)
  }
) async throws -> VendorOnceCommandResult {
  guard arguments == ["vendor-once", "handoff", "--json"] else {
    throw VendorOnceCommandError.invalidArguments
  }

  let firstCode: String
  do {
    firstCode = try generateApprovalCode()
  } catch {
    return try vendorOnceApprovalResult(.unavailable)
  }
  let firstApproval = approval.requestVendorHandoffLaunch(code: firstCode)
  guard firstApproval == .accepted else {
    return try vendorOnceApprovalResult(firstApproval)
  }

  let cancellation = CLITaskCancellation<VendorOnceRuntimeExecution>()
  let monitor = signalMonitorFactory()
  monitor.start { cancellation.request() }
  defer {
    cancellation.clear()
    monitor.stop()
  }
  let gate = CLITaskStartGate()
  let task = Task {
    await gate.wait()
    guard !Task.isCancelled else { return VendorOnceRuntimeExecution.cancelledBeforeHandoff }
    return .report(
      await handoff {
        let secondCode: String
        do {
          secondCode = try generateApprovalCode()
        } catch {
          return .unavailable
        }
        return productApproval(
          await approval.requestVendorHandoffTermination(code: secondCode)
        )
      })
  }
  cancellation.install(task)
  await gate.open()
  switch await task.value {
  case .cancelledBeforeHandoff:
    return try vendorOnceLifecycleResult("cancelled_before_handoff", exitCode: 130)
  case .report(let report):
    return try vendorOnceEncodedResult(report, exitCode: vendorOnceHandoffExitCode(report))
  }
}

func vendorOnceHandoffExitCode(
  _ report: VendorAppNonLogoutHandoffReport
) -> Int32 {
  switch report.outcome {
  case .ready:
    return 0
  case .preflightRejected, .cursorRejected, .launchRejected, .sourceNotReady,
    .terminationRejected, .proofRejected:
    return 69
  case .approvalDenied, .approvalUnavailable:
    return 77
  case .cleanupUnproven:
    return 74
  case .cancelled:
    return 130
  }
}

private func productApproval(
  _ outcome: M2TTYApprovalOutcome
) -> VendorAppNonLogoutHandoffApproval {
  switch outcome {
  case .accepted: return .accepted
  case .denied: return .denied
  case .unavailable: return .unavailable
  }
}

private func vendorOnceApprovalResult(
  _ outcome: M2TTYApprovalOutcome
) throws -> VendorOnceCommandResult {
  try vendorOnceEncodedResult(
    VendorOnceApprovalReport(
      outcome: outcome == .denied ? "approval_denied" : "approval_unavailable"
    ),
    exitCode: 77
  )
}

private enum VendorOnceRuntimeExecution: Sendable {
  case cancelledBeforeHandoff
  case report(VendorAppNonLogoutHandoffReport)
}

private func vendorOnceLifecycleResult(
  _ outcome: String,
  exitCode: Int32
) throws -> VendorOnceCommandResult {
  try vendorOnceEncodedResult(
    VendorOnceApprovalReport(outcome: outcome),
    exitCode: exitCode
  )
}

private func vendorOnceEncodedResult<T: Encodable>(
  _ report: T,
  exitCode: Int32
) throws -> VendorOnceCommandResult {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  return VendorOnceCommandResult(
    standardOutput: String(decoding: try encoder.encode(report), as: UTF8.self),
    exitCode: exitCode
  )
}
