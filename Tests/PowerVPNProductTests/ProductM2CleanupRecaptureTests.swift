import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2CleanupRecaptureTests {
  @Test func pureChangeThenCompleteRetriesOnlyCaptureAndPasses() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [
          cleanupAttempt(.changedDuringCapture),
          .measured(m2CompleteCleanup),
        ]
      )
    ).run(m2CleanupRequest)

    #expect(report.cleanupVerified)
    #expect(report.cleanupCaptureState == .measuredComplete)
    #expect(report.cleanupCaptureRetryReason == .changedDuringCapture)
    #expect(report.cleanupCaptureAttemptCount == 2)
    #expect(report.automaticRetryCount == 0)
    #expect(trace.count("route_enable") == 1)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 2)
    let events = trace.events
    let verifies = events.indices.filter { events[$0] == "verify" }
    #expect(m2EventIndex("route_disable", in: events) < m2EventIndex("stop", in: events))
    #expect(m2EventIndex("stop", in: events) < m2EventIndex("logout", in: events))
    #expect(verifies.count == 2)
    #expect(m2EventIndex("logout", in: events) < (verifies.first ?? 0))
  }

  @Test func helperProcessGenerationMismatchCanSettleOnOneRecapture() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let baseline = try #require(
      m2ObservedNetworkBaseline(generation: m2ColdGeneration).snapshot)
    let after = m2CaptureSnapshotFixture(
      helperGeneration: m2ExitedGeneration,
      vendorProcesses: m2VendorProcessesFixture(charonProcessCount: 1)
    )
    let mismatch = ProductM2CleanupCaptureAttempt(
      before: baseline,
      after: after,
      startRequestSent: true
    )
    #expect(mismatch.state == .helperProcessGenerationInconsistent)

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [mismatch, .measured(m2CompleteCleanup)]
      )
    ).run(m2CleanupRequest)

    #expect(report.cleanupVerified)
    #expect(report.cleanupCaptureState == .measuredComplete)
    #expect(report.cleanupCaptureRetryReason == .helperProcessGenerationInconsistent)
    #expect(report.cleanupCaptureAttemptCount == 2)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
  }

  @Test func twoTransientCapturesStopAtTwoAndFailClosed() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [
          cleanupAttempt(.changedDuringCapture),
          cleanupAttempt(.changedDuringCapture),
          .measured(m2CompleteCleanup),
        ]
      )
    ).run(m2CleanupRequest)

    #expect(report.outcome == .cleanupUnproven)
    #expect(!report.cleanupVerified)
    #expect(report.cleanupCaptureState == .changedDuringCapture)
    #expect(report.cleanupCaptureRetryReason == .changedDuringCapture)
    #expect(report.cleanupCaptureAttemptCount == 2)
    #expect(trace.count("verify") == 2)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
  }

  @Test func mixedTerminalAndChangeNeverRetries() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let baseline = try #require(
      m2ObservedNetworkBaseline(generation: m2ColdGeneration).snapshot)
    let mixed = ProductM2CleanupCaptureAttempt(
      before: baseline,
      after: m2CaptureSnapshotFixture(
        helperGeneration: m2ExitedGeneration,
        helperObservationState: .changedDuringCapture,
        defaultRoute: .unavailable(.commandFailed)
      ),
      startRequestSent: true
    )
    #expect(mixed.state == .commandFailed)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [mixed, .measured(m2CompleteCleanup)]
      )
    ).run(m2CleanupRequest)

    #expect(report.cleanupCaptureState == .commandFailed)
    #expect(report.cleanupCaptureRetryReason == nil)
    #expect(report.cleanupCaptureAttemptCount == 1)
    #expect(trace.count("verify") == 1)
  }

  @Test func completeMeasuredResidueNeverRetries() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let residue = ProductM2CleanupEvidence(
      defaultRouteRestored: true,
      dnsRestored: true,
      interfacesRestored: true,
      utunRestored: true,
      selectedRouteResidueCount: 1,
      surgeStateRestored: true,
      helperGenerationRestored: true
    )
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [.measured(residue), .measured(m2CompleteCleanup)]
      )
    ).run(m2CleanupRequest)

    #expect(!report.cleanupVerified)
    #expect(report.cleanupCaptureState == .measuredComplete)
    #expect(report.cleanupCaptureRetryReason == nil)
    #expect(report.cleanupCaptureAttemptCount == 1)
    #expect(report.cleanupEvidence.selectedRouteResidueCount == 1)
    #expect(trace.count("verify") == 1)
  }

  @Test func deadlineBeforeFirstCaptureStartsNoCaptureAfterTeardown() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onAuthorizationClose: { _ in clock.set(milliseconds: 118_001) }
      )
    ).run(m2CleanupRequest, budget: .start(clock: clock.clock))

    #expect(!report.cleanupVerified)
    #expect(report.cleanupCaptureState == .deadlineExceeded)
    #expect(report.cleanupCaptureRetryReason == nil)
    #expect(report.cleanupCaptureAttemptCount == 0)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 0)
  }

  @Test func deadlineAfterFirstTransientPreventsSecondCapture() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [
          cleanupAttempt(.changedDuringCapture),
          .measured(m2CompleteCleanup),
        ],
        onVerifyCleanup: { _ in clock.set(milliseconds: 118_001) }
      )
    ).run(m2CleanupRequest, budget: .start(clock: clock.clock))

    #expect(!report.cleanupVerified)
    #expect(report.cleanupCaptureState == .deadlineExceeded)
    #expect(report.cleanupCaptureRetryReason == .changedDuringCapture)
    #expect(report.cleanupCaptureAttemptCount == 1)
    #expect(trace.count("verify") == 1)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
  }

  @Test func invalidStopDiagnosticSurvivesCleanupRecapture() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true),
        cleanupAttempts: [
          cleanupAttempt(.changedDuringCapture),
          .measured(m2CompleteCleanup),
        ],
        onStop: { _ in trace.setGeneration(m2ExitedGeneration) }
      )
    ).run(m2CleanupRequest)

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.stopInvalidityClass == .helperExitedSingleGeneration)
    #expect(report.cleanupVerified)
    #expect(report.cleanupCaptureAttemptCount == 2)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("logout") == 1)
  }

  @Test func schemaFourteenKeepsSSHFailureClassAndValueFreeCleanupFields() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: ProductM2TestTrace(),
        sshProof: .rejected,
        cleanupAttempts: [
          cleanupAttempt(.changedDuringCapture),
          .measured(m2CompleteCleanup),
        ]
      )
    ).run(m2CleanupRequest)
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)

    #expect(report.schemaVersion == 14)
    #expect(report.sshProofEvidence?.failureClass == .unclassified)
    #expect(json.contains("\"failureClass\":\"unclassified\""))
    #expect(json.contains("\"cleanupCaptureState\":\"measured_complete\""))
    #expect(json.contains("\"cleanupCaptureRetryReason\":\"changed_during_capture\""))
    #expect(json.contains("\"cleanupCaptureAttemptCount\":2"))
    #expect(json.contains("\"routeActivationAcknowledged\":true"))
    #expect(json.contains("\"routeDeactivationAcknowledged\":true"))
    #expect(!json.contains("com.leadsec"))
    #expect(!json.contains("helper-session-material"))
    #expect(!json.contains("psk-material"))
  }

}

private let m2CleanupRequest = ProductM2ConnectRequest(
  resourceDisplayName: "Campus NC",
  sshTarget: .thu21
)

private func cleanupAttempt(
  _ state: ProductM2CleanupCaptureState
) -> ProductM2CleanupCaptureAttempt {
  ProductM2CleanupCaptureAttempt(
    evidence: .unavailable,
    state: state,
    captureInvoked: true
  )
}
