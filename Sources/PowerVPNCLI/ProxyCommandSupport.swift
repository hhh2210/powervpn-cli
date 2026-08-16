import Foundation
import PowerVPNProduct

enum ProxyExecution: Sendable {
  case success(
    childExitCode: Int32,
    helperMutationRequested: Bool,
    serverContactRequested: Bool,
    cleanupVerified: Bool
  )
  case failure(
    token: String,
    exitCode: Int32,
    runtimeInvoked: Bool,
    helperMutationRequested: Bool,
    serverContactRequested: Bool,
    cleanupVerified: Bool
  )
}
enum ProxyLeaseOperationResult: Sendable {
  case child(ProxyChildRunResult)
  case preChildFailure(String, Int32)
  case cancelled
}

func openAndRun(
  request: ProductM2ConnectRequest,
  startupBudget: ProductM2AbsoluteBudget,
  cleanupBudgetFactory: @escaping @Sendable () -> ProductM2CleanupBudget,
  runtime: @escaping ProxyTunnelOpenOperation,
  operation: @escaping @Sendable (any ProxyTunnelLeasing) async -> ProxyLeaseOperationResult
) async -> ProxyExecution {
  switch await runtime(request, startupBudget) {
  case .failed(let failure):
    return openFailureExecution(failure)
  case .opened(let lease, let mutated, let contacted):
    return await runOpenedLease(
      lease,
      helperMutationRequested: mutated,
      serverContactRequested: contacted,
      cleanupBudgetFactory: cleanupBudgetFactory,
      operation: operation
    )
  }
}

private func openFailureExecution(_ failure: ProxyTunnelOpenFailure) -> ProxyExecution {
  if failure.failure == .cleanupUnproven
    || (failure.helperMutationRequested && !failure.cleanupVerified)
  {
    return .failure(
      token: "cleanup_unproven",
      exitCode: 74,
      runtimeInvoked: true,
      helperMutationRequested: failure.helperMutationRequested,
      serverContactRequested: failure.serverContactRequested,
      cleanupVerified: failure.cleanupVerified
    )
  }
  if failure.failure == .cancelled {
    return .failure(
      token: "cancelled",
      exitCode: 130,
      runtimeInvoked: true,
      helperMutationRequested: failure.helperMutationRequested,
      serverContactRequested: failure.serverContactRequested,
      cleanupVerified: failure.cleanupVerified
    )
  }
  return .failure(
    token: tunnelOpenFailureToken(failure),
    exitCode: failure.helperMutationRequested ? 70 : 69,
    runtimeInvoked: true,
    helperMutationRequested: failure.helperMutationRequested,
    serverContactRequested: failure.serverContactRequested,
    cleanupVerified: failure.cleanupVerified
  )
}

private func tunnelOpenFailureToken(_ failure: ProxyTunnelOpenFailure) -> String {
  var token = "tunnel_open_failed:\(failure.failure?.rawValue ?? "unclassified")"
  if let firstBadEvent = failure.firstBadEvent {
    token += ":first_bad=\(firstBadEvent.rawValue)"
  }
  return token
}

private func runOpenedLease(
  _ lease: any ProxyTunnelLeasing,
  helperMutationRequested: Bool,
  serverContactRequested: Bool,
  cleanupBudgetFactory: @escaping @Sendable () -> ProductM2CleanupBudget,
  operation: @escaping @Sendable (any ProxyTunnelLeasing) async -> ProxyLeaseOperationResult
) async -> ProxyExecution {
  let operationResult = Task.isCancelled ? .cancelled : await operation(lease)
  let shutdown = await Task.detached {
    await lease.shutdown(budget: cleanupBudgetFactory())
  }.value
  guard shutdown.cleanupVerified else {
    return .failure(
      token: "cleanup_unproven",
      exitCode: 74,
      runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: false
    )
  }
  let finalOperationResult: ProxyLeaseOperationResult =
    Task.isCancelled ? .cancelled : operationResult
  switch finalOperationResult {
  case .cancelled:
    return .failure(
      token: "cancelled",
      exitCode: 130,
      runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: true
    )
  case .preChildFailure(let token, let exitCode):
    return .failure(
      token: token,
      exitCode: exitCode,
      runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: true
    )
  case .child(let result):
    return childExecution(
      result,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested
    )
  }
}

private func childExecution(
  _ result: ProxyChildRunResult,
  helperMutationRequested: Bool,
  serverContactRequested: Bool
) -> ProxyExecution {
  switch result.outcome {
  case .cancelled:
    return .failure(
      token: "cancelled", exitCode: 130, runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: true)
  case .spawnFailed:
    return .failure(
      token: "child_spawn_failed", exitCode: 70, runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: true)
  case .readinessFailed:
    return .failure(
      token: "forward_not_ready", exitCode: 70, runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: true)
  case .exited(let code):
    if code == 0 {
      return .success(
        childExitCode: 0,
        helperMutationRequested: helperMutationRequested,
        serverContactRequested: serverContactRequested,
        cleanupVerified: true)
    }
    return .failure(
      token: "child_failed", exitCode: code, runtimeInvoked: true,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested,
      cleanupVerified: true)
  }
}

func requestProxyApproval(
  request: ProductM2ConnectRequest,
  nonInteractive: Bool,
  generateCode: @escaping @Sendable () throws -> String,
  approval: M2TTYApproval
) -> String? {
  guard !nonInteractive else { return nil }
  let code: String
  do {
    code = try generateCode()
  } catch {
    return "approval_unavailable"
  }
  switch approval.request(
    code: code,
    resourceDisplayName: request.resourceDisplayName,
    sshTarget: request.sshTarget.rawValue
  ) {
  case .accepted: return nil
  case .denied: return "approval_denied"
  case .unavailable: return "approval_unavailable"
  }
}

func runProxySignalTask(
  signalMonitorFactory: CLISignalMonitorFactory,
  operation: @escaping @Sendable () async -> ProxyCommandResult
) async -> ProxyCommandResult {
  let cancellation = CLITaskCancellation<ProxyCommandResult>()
  let monitor = signalMonitorFactory()
  monitor.start { cancellation.request() }
  defer {
    cancellation.clear()
    monitor.stop()
  }
  let gate = CLITaskStartGate()
  let task = Task {
    await gate.wait()
    guard !Task.isCancelled else {
      return proxyHumanResult(error: "cancelled", exitCode: 130)
    }
    return await operation()
  }
  cancellation.install(task)
  await gate.open()
  return await task.value
}

func runProxySignalExecution(
  signalMonitorFactory: CLISignalMonitorFactory,
  operation: @escaping @Sendable () async -> ProxyExecution
) async -> ProxyExecution {
  let cancellation = CLITaskCancellation<ProxyExecution>()
  let monitor = signalMonitorFactory()
  monitor.start { cancellation.request() }
  defer {
    cancellation.clear()
    monitor.stop()
  }
  let gate = CLITaskStartGate()
  let task = Task {
    await gate.wait()
    guard !Task.isCancelled else {
      return ProxyExecution.failure(
        token: "cancelled", exitCode: 130, runtimeInvoked: false,
        helperMutationRequested: false, serverContactRequested: false,
        cleanupVerified: false)
    }
    return await operation()
  }
  cancellation.install(task)
  await gate.open()
  return await task.value
}

func proxyHumanResult(execution: ProxyExecution) -> ProxyCommandResult {
  switch execution {
  case .success:
    return ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
  case .failure(let token, let exitCode, _, _, _, _):
    return proxyHumanResult(error: token, exitCode: exitCode)
  }
}

func proxyHumanResult(error: String, exitCode: Int32) -> ProxyCommandResult {
  ProxyCommandResult(
    standardOutput: "",
    standardError: "\(error)\n",
    exitCode: exitCode
  )
}

private struct ProxyServeReport: Encodable {
  let schemaVersion = 1
  let outcome: String
  let runtimeInvoked: Bool
  let helperMutationRequested: Bool
  let serverContactRequested: Bool
  let cleanupVerified: Bool
  let containsSecrets = false
}
private enum ProxyServeEncodingError: Error {
  case invalidUTF8
}

func proxyServeResult(
  invocation: ProxyServeInvocation,
  execution: ProxyExecution
) throws -> ProxyCommandResult {
  let report: ProxyServeReport
  let error: String
  let exitCode: Int32
  switch execution {
  case .success(_, let mutated, let contacted, let cleanupVerified):
    report = ProxyServeReport(
      outcome: "child_exited",
      runtimeInvoked: true,
      helperMutationRequested: mutated,
      serverContactRequested: contacted,
      cleanupVerified: cleanupVerified
    )
    error = ""
    exitCode = 0
  case .failure(
    let token, let code, let runtimeInvoked, let mutated, let contacted, let cleanupVerified
  ):
    report = ProxyServeReport(
      outcome: token,
      runtimeInvoked: runtimeInvoked,
      helperMutationRequested: mutated,
      serverContactRequested: contacted,
      cleanupVerified: cleanupVerified
    )
    error = "\(token)\n"
    exitCode = code
  }
  let output: String
  if invocation.json {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(report)
    guard let document = String(data: data, encoding: .utf8) else {
      throw ProxyServeEncodingError.invalidUTF8
    }
    output = document + "\n"
  } else {
    output = ""
  }
  return ProxyCommandResult(
    standardOutput: output,
    standardError: error,
    exitCode: exitCode
  )
}
