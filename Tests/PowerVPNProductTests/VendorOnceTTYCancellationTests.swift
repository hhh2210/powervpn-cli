import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct VendorOnceTTYCancellationTests {
  @Test func secondApprovalSignalReturnsCancelledWithinTwoHundredMilliseconds() async throws {
    let monitor = VendorOnceCancellationSignalMonitor()
    let worker = VendorOnceSyntheticBlockingRead()
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace
      )
    )
    let approval = M2TTYApproval(
      exchange: { _ in .line("A1B2C3D4") },
      asyncExchange: { _, _ in
        await M2TTYApproval.runCancellableBlockingExchange(worker.read)
      }
    )

    let command = Task {
      try await runVendorOnceCommand(
        ["vendor-once", "handoff", "--json"],
        generateApprovalCode: { "A1B2C3D4" },
        approval: approval,
        signalMonitorFactory: { monitor },
        handoff: { secondApproval in
          await coordinator.run(secondApproval: secondApproval)
        }
      )
    }
    #expect(worker.waitUntilStarted())
    let started = ContinuousClock.now
    monitor.trigger()
    let result = try await command.value
    let elapsed = started.duration(to: .now)

    #expect(elapsed < .milliseconds(200))
    #expect(result.exitCode == 130)
    #expect(result.standardOutput.contains("\"outcome\" : \"cancelled\""))
    #expect(!result.standardOutput.contains("A1B2C3D4"))
    #expect(application.forceCount == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func secondApprovalHasTenMinuteBoundAndTimeoutIsUnavailable() async {
    let observation = VendorOnceAsyncExchangeObservation()
    let approval = M2TTYApproval(
      exchange: { _ in .unavailable },
      asyncExchange: { prompt, timeoutMilliseconds in
        observation.capture(prompt: prompt, timeoutMilliseconds: timeoutMilliseconds)
        return .unavailable
      }
    )

    let result = await approval.requestVendorHandoffTermination(code: "A1B2C3D4")

    #expect(result == .unavailable)
    #expect(observation.timeoutMilliseconds == 600_000)
    #expect(observation.prompt.contains("expires after 10 minutes"))
  }

  @Test func firstAndM2ApprovalsRemainSynchronous() {
    let observation = VendorOnceAsyncExchangeObservation()
    let approval = M2TTYApproval(
      exchange: { _ in .line("A1B2C3D4") },
      asyncExchange: { prompt, timeoutMilliseconds in
        observation.capture(prompt: prompt, timeoutMilliseconds: timeoutMilliseconds)
        return .unavailable
      }
    )

    #expect(approval.requestVendorHandoffLaunch(code: "A1B2C3D4") == .accepted)
    #expect(
      approval.request(
        code: "A1B2C3D4",
        resourceDisplayName: "login21",
        sshTarget: "thu21"
      ) == .accepted
    )
    #expect(observation.invocationCount == 0)
  }
}

private final class VendorOnceSyntheticBlockingRead: @unchecked Sendable {
  private let condition = NSCondition()
  private var started = false

  func read() -> M2TTYLineRead {
    condition.lock()
    started = true
    condition.broadcast()
    condition.unlock()
    while !Task.isCancelled { usleep(50_000) }
    return .unavailable
  }

  func waitUntilStarted() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date().addingTimeInterval(1)
    while !started {
      guard condition.wait(until: deadline) else { return started }
    }
    return true
  }
}

private final class VendorOnceCancellationSignalMonitor: CLISignalMonitoring,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?

  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock { self.handler = handler }
  }

  func stop() { lock.withLock { handler = nil } }
  func trigger() { lock.withLock { handler }?() }
}

private final class VendorOnceAsyncExchangeObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var storedPrompt = ""
  private var storedTimeoutMilliseconds: UInt64 = 0
  private var storedInvocationCount = 0

  func capture(prompt: String, timeoutMilliseconds: UInt64) {
    lock.withLock {
      storedPrompt = prompt
      storedTimeoutMilliseconds = timeoutMilliseconds
      storedInvocationCount += 1
    }
  }

  var prompt: String { lock.withLock { storedPrompt } }
  var timeoutMilliseconds: UInt64 { lock.withLock { storedTimeoutMilliseconds } }
  var invocationCount: Int { lock.withLock { storedInvocationCount } }
}
