import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct VendorOnceCommandTests {
  @Test func firstApprovalPrecedesLazyCoordinatorAndSecondApprovalUsesNewCode() async throws {
    let trace = VendorOnceCommandTrace()
    let codes = VendorOnceCodeSequence(["A1B2C3D4", "B1C2D3E4"])
    let approval = M2TTYApproval(exchange: { prompt in
      let index = trace.captureApproval(prompt)
      return .line(index == 1 ? "A1B2C3D4" : "B1C2D3E4")
    })

    let result = try await runVendorOnceCommand(
      ["vendor-once", "handoff", "--json"],
      generateApprovalCode: {
        let code = try codes.next()
        trace.record("code:\(code)")
        return code
      },
      approval: approval,
      signalMonitorFactory: { VendorOnceNoopSignalMonitor() },
      handoff: { secondApproval in
        trace.record("coordinator")
        let outcome = secondApproval()
        trace.record("second:\(outcome.rawValue)")
        return syntheticHandoffReport(.ready, secondApproval: outcome)
      }
    )

    #expect(result.exitCode == 0)
    #expect(
      trace.events == [
        "code:A1B2C3D4", "approval:1", "coordinator",
        "code:B1C2D3E4", "approval:2", "second:accepted",
      ])
    let prompts = trace.prompts
    #expect(prompts.count == 2)
    for marker in ["normally launch", "official PowerVPN App", "log in", "second approval"] {
      #expect(prompts[0].contains(marker))
    }
    for marker in ["normal login", "login21 connected", "forceTerminate", "exact App receiver"] {
      #expect(prompts[1].contains(marker))
    }
    #expect(prompts[1].contains("will not use Cmd-Q"))
    #expect(!result.standardOutput.contains("A1B2C3D4"))
    #expect(!result.standardOutput.contains("B1C2D3E4"))
    #expect(result.standardOutput.contains("\"outcome\" : \"ready\""))
    #expect(result.standardOutput.contains("\"normalQuitRequested\" : false"))
    assertSortedJSON(result.standardOutput)
  }

  @Test func firstDenialUnavailableOrRandomFailureNeverInvokesCoordinator() async throws {
    let cases: [(M2TTYLineRead?, Bool)] = [
      (.line("A1B2C3D5"), false),
      (.unavailable, false),
      (nil, true),
    ]
    for (response, randomFails) in cases {
      let trace = VendorOnceCommandTrace()
      let result = try await runVendorOnceCommand(
        ["vendor-once", "handoff", "--json"],
        generateApprovalCode: {
          trace.record("code")
          if randomFails { throw VendorOnceTestError.random }
          return "A1B2C3D4"
        },
        approval: M2TTYApproval(exchange: { _ in
          trace.record("approval")
          return response ?? .unavailable
        }),
        signalMonitorFactory: { VendorOnceNoopSignalMonitor() },
        handoff: { _ in
          trace.record("coordinator")
          return syntheticHandoffReport(.ready)
        }
      )

      #expect(result.exitCode == 77)
      #expect(trace.count("coordinator") == 0)
      #expect(trace.count("approval") == (randomFails ? 0 : 1))
      #expect(result.standardOutput.contains("\"containsSecrets\" : false"))
      #expect(result.standardOutput.contains("\"productCoordinatorConstructed\" : false"))
      #expect(!result.standardOutput.contains("A1B2C3D4"))
      assertSortedJSON(result.standardOutput)
    }
  }

  @Test func secondDenialAndUnavailableMapToExit77WithoutCodes() async throws {
    for secondResponse in [M2TTYLineRead.line("B1C2D3E5"), .unavailable] {
      let trace = VendorOnceCommandTrace()
      let codes = VendorOnceCodeSequence(["A1B2C3D4", "B1C2D3E4"])
      let result = try await runVendorOnceCommand(
        ["vendor-once", "handoff", "--json"],
        generateApprovalCode: { try codes.next() },
        approval: M2TTYApproval(exchange: { prompt in
          trace.captureApproval(prompt) == 1 ? .line("A1B2C3D4") : secondResponse
        }),
        signalMonitorFactory: { VendorOnceNoopSignalMonitor() },
        handoff: { secondApproval in
          trace.record("coordinator")
          let approval = secondApproval()
          return syntheticHandoffReport(
            approval == .denied ? .approvalDenied : .approvalUnavailable,
            secondApproval: approval
          )
        }
      )

      #expect(result.exitCode == 77)
      #expect(trace.count("coordinator") == 1)
      #expect(trace.prompts.count == 2)
      #expect(!result.standardOutput.contains("A1B2C3D4"))
      #expect(!result.standardOutput.contains("B1C2D3E4"))
      assertSortedJSON(result.standardOutput)
    }
  }

  @Test func productOutcomesHaveExactExitMapping() {
    let expected: [(VendorAppNonLogoutHandoffOutcome, Int32)] = [
      (.ready, 0),
      (.preflightRejected, 69),
      (.cursorRejected, 69),
      (.launchRejected, 69),
      (.sourceNotReady, 69),
      (.terminationRejected, 69),
      (.proofRejected, 69),
      (.approvalDenied, 77),
      (.approvalUnavailable, 77),
      (.cleanupUnproven, 74),
      (.cancelled, 130),
    ]
    for (outcome, exitCode) in expected {
      #expect(vendorOnceHandoffExitCode(syntheticHandoffReport(outcome)) == exitCode)
    }
  }

  @Test func malformedAndLegacyBeginGrammarFailBeforeAnyApprovalOrCoordinator() async {
    for arguments in [
      ["vendor-once", "begin", "--json"],
      ["vendor-once", "handoff"],
      ["vendor-once", "handoff", "--json", "--yes"],
      ["vendor-once", "status", "--json"],
    ] {
      let trace = VendorOnceCommandTrace()
      do {
        _ = try await runVendorOnceCommand(
          arguments,
          generateApprovalCode: {
            trace.record("code")
            return "A1B2C3D4"
          },
          approval: M2TTYApproval(exchange: { _ in
            trace.record("approval")
            return .line("A1B2C3D4")
          }),
          signalMonitorFactory: { VendorOnceNoopSignalMonitor() },
          handoff: { _ in
            trace.record("coordinator")
            return syntheticHandoffReport(.ready)
          }
        )
        Issue.record("expected usage rejection")
      } catch let error as VendorOnceCommandError {
        #expect(error == .invalidArguments)
        #expect(error.description == "usage: powervpn vendor-once handoff --json")
      } catch {
        Issue.record("unexpected error: \(error)")
      }
      #expect(trace.events.isEmpty)
    }
  }

  @Test func signalAfterHandoffStartsStillAwaitsShieldedTerminalReport() async throws {
    let monitor = VendorOnceNoopSignalMonitor()
    let handoffStarted = VendorOnceAsyncGate()
    let result = try await runVendorOnceCommand(
      ["vendor-once", "handoff", "--json"],
      generateApprovalCode: { "A1B2C3D4" },
      approval: M2TTYApproval(exchange: { _ in .line("A1B2C3D4") }),
      signalMonitorFactory: { monitor },
      handoff: { _ in
        await handoffStarted.open()
        monitor.trigger()
        return await Task.detached { syntheticHandoffReport(.ready) }.value
      }
    )

    #expect(await handoffStarted.wasOpened)
    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("\"outcome\" : \"ready\""))
  }
}

private func syntheticHandoffReport(
  _ outcome: VendorAppNonLogoutHandoffOutcome,
  secondApproval: VendorAppNonLogoutHandoffApproval? = nil
) -> VendorAppNonLogoutHandoffReport {
  VendorAppNonLogoutHandoffReport(
    outcome: outcome,
    baselineStable: outcome != .preflightRejected,
    cursorPersisted: outcome == .ready,
    officialAppLaunched: secondApproval != nil,
    secondApproval: secondApproval,
    forceTerminationAccepted: outcome == .ready,
    exactReceiverTerminated: outcome == .ready,
    sourceSnapshotComplete: outcome == .ready,
    proofPersisted: outcome == .ready,
    officialAppStillRunning: false,
    cleanup: nil
  )
}

private enum VendorOnceTestError: Error { case random }

private final class VendorOnceCodeSequence: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [String]

  init(_ values: [String]) { self.values = values }

  func next() throws -> String {
    try lock.withLock {
      guard !values.isEmpty else { throw VendorOnceTestError.random }
      return values.removeFirst()
    }
  }
}

private final class VendorOnceCommandTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedEvents: [String] = []
  private var storedPrompts: [String] = []

  func record(_ event: String) { lock.withLock { storedEvents.append(event) } }

  func captureApproval(_ prompt: String) -> Int {
    lock.withLock {
      storedPrompts.append(prompt)
      let index = storedPrompts.count
      storedEvents.append("approval:\(index)")
      return index
    }
  }

  var events: [String] { lock.withLock { storedEvents } }
  var prompts: [String] { lock.withLock { storedPrompts } }
  func count(_ event: String) -> Int { lock.withLock { storedEvents.count { $0 == event } } }
}

private final class VendorOnceNoopSignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?

  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock { self.handler = handler }
  }

  func stop() { lock.withLock { handler = nil } }
  func trigger() { lock.withLock { handler }?() }
}

private actor VendorOnceAsyncGate {
  private(set) var wasOpened = false
  func open() { wasOpened = true }
}
