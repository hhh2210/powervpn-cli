import Foundation
import PowerVPNPortal
import PowerVPNProduct

func runCurrentMachineProxyCommand(
  _ arguments: [String],
  loadConfiguration: @escaping @Sendable () throws -> PowerVPNTargetsConfiguration = {
    try PowerVPNTargetsConfiguration.currentMachine()
  }
) async throws -> ProxyCommandResult {
  guard let subcommand = arguments.dropFirst().first,
    subcommand == "ssh" || subcommand == "serve"
  else { throw ProxyCommandError.invalidSSHArguments }
  let targetKey: String
  if subcommand == "ssh" {
    targetKey = try parseProxySSHInvocation(arguments).request.sshTarget.rawValue
  } else {
    targetKey = try parseProxyServeInvocation(arguments).request.sshTarget.rawValue
  }

  let configuration: PowerVPNTargetsConfiguration
  do {
    configuration = try loadConfiguration()
  } catch let error as PowerVPNTargetsConfigurationError {
    return proxyHumanResult(error: error.token, exitCode: 69)
  }
  do {
    _ = try ProductM2SSHTarget(key: targetKey, configuration: configuration)
  } catch let error as PowerVPNTargetsConfigurationError {
    return proxyHumanResult(error: error.token, exitCode: 69)
  }
  let resolveTarget: @Sendable (String) throws -> ProductM2SSHTarget = { key in
    try ProductM2SSHTarget(key: key, configuration: configuration)
  }
  let runtime = ProductPersistentTunnelRuntime(configuration: configuration)
  let open: ProxyTunnelOpenOperation = { request, budget in
    await openProductProxyTunnel(
      runtime: runtime,
      request: request,
      budget: budget
    )
  }
  let availability: @Sendable () -> ProductM2AuthorizationFailure? = {
    runtime.authorizationAvailabilityFailure
  }
  if subcommand == "ssh" {
    return try await runProxySSHCommand(
      arguments,
      authorizationAvailabilityFailure: availability,
      resolveTarget: resolveTarget,
      runtime: open
    )
  }
  return try await runProxyServeCommand(
    arguments,
    authorizationAvailabilityFailure: availability,
    resolveTarget: resolveTarget,
    runtime: open
  )
}

func runProxySSHCommand(
  _ arguments: [String],
  authorizationAvailabilityFailure: @escaping @Sendable () -> ProductM2AuthorizationFailure?,
  generateApprovalCode: @escaping @Sendable () throws -> String = M2TTYApproval.secureCode,
  resolveTarget: @escaping @Sendable (String) throws -> ProductM2SSHTarget = {
    guard let target = ProductM2SSHTarget(rawValue: $0) else {
      throw ProxyCommandError.invalidSSHArguments
    }
    return target
  },
  approval: M2TTYApproval = M2TTYApproval(),
  signalMonitorFactory: CLISignalMonitorFactory = { DarwinCLISignalMonitor() },
  startupBudgetFactory: @escaping @Sendable () -> ProductM2AbsoluteBudget = {
    ProductM2AbsoluteBudget.start()
  },
  cleanupBudgetFactory: @escaping @Sendable () -> ProductM2CleanupBudget = {
    ProductM2CleanupBudget.start()
  },
  childRunner: any ProxyChildRunning = FoundationProxyChildRunner(),
  runtime: @escaping ProxyTunnelOpenOperation
) async throws -> ProxyCommandResult {
  let invocation = try parseProxySSHInvocation(arguments, resolveTarget: resolveTarget)
  if authorizationAvailabilityFailure() != nil {
    return proxyHumanResult(error: "runtime_unavailable", exitCode: 69)
  }
  if let approvalFailure = requestProxyApproval(
    request: invocation.request,
    nonInteractive: invocation.nonInteractive,
    generateCode: generateApprovalCode,
    approval: approval
  ) {
    return proxyHumanResult(error: approvalFailure, exitCode: 77)
  }

  return await runProxySignalTask(signalMonitorFactory: signalMonitorFactory) {
    await performProxySSH(
      invocation,
      startupBudget: startupBudgetFactory(),
      cleanupBudgetFactory: cleanupBudgetFactory,
      childRunner: childRunner,
      runtime: runtime
    )
  }
}

func runProxyServeCommand(
  _ arguments: [String],
  authorizationAvailabilityFailure: @escaping @Sendable () -> ProductM2AuthorizationFailure?,
  resolveTarget: @escaping @Sendable (String) throws -> ProductM2SSHTarget = {
    guard let target = ProductM2SSHTarget(rawValue: $0) else {
      throw ProxyCommandError.invalidServeArguments
    }
    return target
  },
  generateApprovalCode: @escaping @Sendable () throws -> String = M2TTYApproval.secureCode,
  approval: M2TTYApproval = M2TTYApproval(),
  signalMonitorFactory: CLISignalMonitorFactory = { DarwinCLISignalMonitor() },
  startupBudgetFactory: @escaping @Sendable () -> ProductM2AbsoluteBudget = {
    ProductM2AbsoluteBudget.start()
  },
  cleanupBudgetFactory: @escaping @Sendable () -> ProductM2CleanupBudget = {
    ProductM2CleanupBudget.start()
  },
  childRunner: any ProxyChildRunning = FoundationProxyChildRunner(),
  emitReadiness: @escaping @Sendable () -> Void = {
    FileHandle.standardError.write(Data("proxy_ready\n".utf8))
  },
  runtime: @escaping ProxyTunnelOpenOperation
) async throws -> ProxyCommandResult {
  let invocation = try parseProxyServeInvocation(arguments, resolveTarget: resolveTarget)
  if authorizationAvailabilityFailure() != nil {
    return try proxyServeResult(
      invocation: invocation,
      execution: .failure(
        token: "runtime_unavailable",
        exitCode: 69,
        runtimeInvoked: false,
        helperMutationRequested: false,
        serverContactRequested: false,
        cleanupVerified: false
      )
    )
  }
  if let approvalFailure = requestProxyApproval(
    request: invocation.request,
    nonInteractive: invocation.nonInteractive,
    generateCode: generateApprovalCode,
    approval: approval
  ) {
    return try proxyServeResult(
      invocation: invocation,
      execution: .failure(
        token: approvalFailure,
        exitCode: 77,
        runtimeInvoked: false,
        helperMutationRequested: false,
        serverContactRequested: false,
        cleanupVerified: false
      )
    )
  }

  let childExecution = ProxyServeChildExecution(
    runner: childRunner,
    emitReadiness: emitReadiness
  )
  let execution = await runProxySignalExecution(signalMonitorFactory: signalMonitorFactory) {
    await performProxyServe(
      invocation,
      startupBudget: startupBudgetFactory(),
      cleanupBudgetFactory: cleanupBudgetFactory,
      childExecution: childExecution,
      runtime: runtime
    )
  }
  return try proxyServeResult(invocation: invocation, execution: execution)
}

private func performProxySSH(
  _ invocation: ProxySSHInvocation,
  startupBudget: ProductM2AbsoluteBudget,
  cleanupBudgetFactory: @escaping @Sendable () -> ProductM2CleanupBudget,
  childRunner: any ProxyChildRunning,
  runtime: @escaping ProxyTunnelOpenOperation
) async -> ProxyCommandResult {
  let execution = await openAndRun(
    request: invocation.request,
    startupBudget: startupBudget,
    cleanupBudgetFactory: cleanupBudgetFactory,
    runtime: runtime
  ) { lease in
    guard await lease.permitsIPv4(invocation.destinationIPv4) else {
      return .preChildFailure("target_not_covered", 70)
    }
    guard !Task.isCancelled else { return .cancelled }
    let result = await childRunner.run(
      ProxyChildSpecification(
        executable: "/usr/bin/nc",
        arguments: [invocation.destinationText, String(invocation.destinationPort)],
        standardInput: .inherited,
        standardOutput: .inherited
      ),
      readiness: .none,
      onReady: {}
    )
    return .child(result)
  }
  return proxyHumanResult(execution: execution)
}

private struct ProxyServeChildExecution: Sendable {
  let runner: any ProxyChildRunning
  let emitReadiness: @Sendable () -> Void
}

private func performProxyServe(
  _ invocation: ProxyServeInvocation,
  startupBudget: ProductM2AbsoluteBudget,
  cleanupBudgetFactory: @escaping @Sendable () -> ProductM2CleanupBudget,
  childExecution: ProxyServeChildExecution,
  runtime: @escaping ProxyTunnelOpenOperation
) async -> ProxyExecution {
  await openAndRun(
    request: invocation.request,
    startupBudget: startupBudget,
    cleanupBudgetFactory: cleanupBudgetFactory,
    runtime: runtime
  ) { _ in
    guard !Task.isCancelled else { return .cancelled }
    let port = String(invocation.listenPort)
    let result = await childExecution.runner.run(
      ProxyChildSpecification(
        executable: "/usr/bin/ssh",
        arguments: [
          "-N", "-T", "-D", "127.0.0.1:\(port)",
          "-o", "ExitOnForwardFailure=yes",
          "-o", "BatchMode=yes",
          "-o", "ServerAliveInterval=15",
          "-o", "ServerAliveCountMax=3",
          "-o", "ConnectTimeout=10",
          invocation.request.sshTarget.rawValue,
        ],
        standardInput: .null,
        standardOutput: .null
      ),
      readiness: .loopback(port: invocation.listenPort, timeoutMilliseconds: 10_000),
      onReady: childExecution.emitReadiness
    )
    return .child(result)
  }
}
