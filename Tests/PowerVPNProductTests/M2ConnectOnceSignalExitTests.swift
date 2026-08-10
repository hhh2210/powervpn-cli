import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct M2ConnectOnceSignalExitTests {
  @Test func earlyRepeatedSignalsCancelBeforeRuntimeConstruction() async throws {
    let trace = M2CommandTrace()
    let monitor = M2ManualSignalMonitor(emitOnStart: 2)
    let result = try await runM2ConnectOnceCommand(
      m2ValidArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: { "A1B2C3D4" },
      approval: approval(trace: trace, response: .line("A1B2C3D4")),
      signalMonitorFactory: { monitor },
      runtime: { _, _ in
        trace.record("runtime")
        return successReport()
      }
    )

    #expect(result.exitCode == 130)
    #expect(trace.count("runtime") == 0)
    #expect(monitor.startCount == 1)
    #expect(monitor.stopCount == 1)
    assertSortedJSON(result.standardOutput)
  }

  @Test func activeRepeatedSignalAwaitsCancelledRuntimeReport() async throws {
    let monitor = M2ManualSignalMonitor()
    let runtime = M2CancellationRuntime()
    let command = Task {
      try await runM2ConnectOnceCommand(
        m2ValidArguments,
        authorizationAvailabilityFailure: { nil },
        generateApprovalCode: { "A1B2C3D4" },
        approval: M2TTYApproval(exchange: { _ in .line("A1B2C3D4") }),
        signalMonitorFactory: { monitor },
        runtime: runtime.run
      )
    }
    #expect(runtime.waitUntilStarted())
    monitor.emit(times: 2)
    let result = try await command.value

    #expect(result.exitCode == 130)
    #expect(runtime.invocationCount == 1)
    #expect(runtime.cancellationCount == 1)
    #expect(monitor.stopCount == 1)
  }

  @Test func workCutoffCancelsRuntimeAndAwaitsItsCleanupReport() async throws {
    let monitor = M2ManualSignalMonitor()
    let runtime = M2CancellationRuntime()
    let deadline = M2ManualDeadline()
    let command = Task {
      try await runM2ConnectOnceCommand(
        m2ValidArguments,
        authorizationAvailabilityFailure: { nil },
        generateApprovalCode: { "A1B2C3D4" },
        approval: M2TTYApproval(exchange: { _ in .line("A1B2C3D4") }),
        signalMonitorFactory: { monitor },
        workCutoffAlarm: { _ in await deadline.wait() },
        runtime: runtime.run
      )
    }
    #expect(runtime.waitUntilStarted())
    await deadline.fire()
    let result = try await command.value

    #expect(result.exitCode == 130)
    #expect(runtime.invocationCount == 1)
    #expect(runtime.cancellationCount == 1)
    #expect(monitor.stopCount == 1)
  }

  @Test func exitMappingHonorsCleanupAndCancellationPriority() {
    #expect(m2ConnectOnceExitCode(successReport()) == 0)
    #expect(m2ConnectOnceExitCode(report(outcome: .preflightBlocked)) == 69)
    #expect(m2ConnectOnceExitCode(report(outcome: .sshProofRejected, mutated: true)) == 70)
    #expect(
      m2ConnectOnceExitCode(
        report(outcome: .cleanupUnproven, cleanup: false, mutated: false)) == 74)
    #expect(
      m2ConnectOnceExitCode(
        report(outcome: .cancelled, cleanup: false, mutated: true)) == 74)
    #expect(
      m2ConnectOnceExitCode(
        report(outcome: .connectedAndCleanedUp, cleanup: false, mutated: true)) == 74)
    #expect(
      m2ConnectOnceExitCode(
        report(outcome: .deadlineExceeded, cleanup: false, mutated: true)) == 74)
    #expect(m2ConnectOnceExitCode(report(outcome: .deadlineExceeded)) == 124)
    #expect(m2ConnectOnceExitCode(report(outcome: .cancelled)) == 130)
    #expect(m2ConnectOnceExitCode(successReport(finalState: .connected)) == 1)
  }
}

private actor M2ManualDeadline {
  private var fired = false
  private var continuation: CheckedContinuation<Void, Never>?

  func wait() async {
    guard !fired else { return }
    await withCheckedContinuation { continuation = $0 }
  }

  func fire() {
    fired = true
    continuation?.resume()
    continuation = nil
  }
}
