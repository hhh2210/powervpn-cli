import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2CleanupDeadlineTests {
  @Test(arguments: ProductM2LateCleanupStage.allCases)
  func aLateStagePreservesItsEvidenceButCannotVerifyCleanup(
    _ lateStage: ProductM2LateCleanupStage
  ) async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onAuthorizationClose: { _ in
          if lateStage == .authorization {
            clock.set(milliseconds: 94_001)
          }
        },
        onVerifyCleanup: { _ in
          if lateStage == .verification {
            clock.set(milliseconds: 118_001)
          }
        },
        onStop: { _ in
          if lateStage == .control {
            clock.set(milliseconds: 73_001)
          }
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.finalState == .failed)
    #expect(!report.cleanupVerified)
    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.authorizationClose == .accepted)
    #expect(report.authorizationOwnedMaterialErased)
    #expect(report.cleanupEvidence == m2CompleteCleanup)
    #expect(
      report.cleanupPath
        == (lateStage == .control ? .cleanupUnproven : .sameLeaseStop))
  }

  @Test func lateEmergencyPreservesBothReceiptsButInvalidatesTheCleanupPath() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(
          outcome: .connectionInvalid,
          requestSent: false
        ),
        onEmergencyStop: { _ in clock.set(milliseconds: 73_001) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.cleanupPath == .cleanupUnproven)
    #expect(!report.cleanupVerified)
    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.emergencyStopOutcome == .transportAcknowledged)
    #expect(report.authorizationClose == .accepted)
    #expect(report.cleanupEvidence == m2CompleteCleanup)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 1)
  }

  @Test func expiredControlStageUsesReportBudgetForOneBoundedStop() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let timeouts = ProductM2StopTimeoutRecorder()
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onProveFreshSSH: { _ in clock.set(milliseconds: 73_001) },
        onStop: timeouts.record
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: .start(clock: clock.clock)
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(!report.cleanupVerified)
    #expect(timeouts.values == [2_000])
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
  }

  @Test func expiredControlStageFallsBackToEmergencyOnlyAfterUnsentStop() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let stopTimeouts = ProductM2StopTimeoutRecorder()
    let emergencyTimeouts = ProductM2StopTimeoutRecorder()
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(
          outcome: .connectionInvalid,
          requestSent: false
        ),
        onProveFreshSSH: { _ in clock.set(milliseconds: 73_001) },
        onStop: stopTimeouts.record,
        onEmergencyStop: emergencyTimeouts.record
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: .start(clock: clock.clock)
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.emergencyStopOutcome == .transportAcknowledged)
    #expect(!report.cleanupVerified)
    #expect(stopTimeouts.values == [2_000])
    #expect(emergencyTimeouts.values == [2_000])
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 1)
  }

  @Test func sentFallbackStopFailureNeverRepeatsWithEmergencyStop() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(
          outcome: .timeout,
          requestSent: true
        ),
        onProveFreshSSH: { _ in clock.set(milliseconds: 73_001) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: .start(clock: clock.clock)
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.stopOutcome == .timeout)
    #expect(report.emergencyStopOutcome == .notAttempted)
    #expect(!report.cleanupVerified)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
  }

  @Test func exhaustedReportBudgetKeepsStopUnsentAndCleanupUnverified() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onProveFreshSSH: { _ in clock.set(milliseconds: 120_001) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: .start(clock: clock.clock)
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(report.cleanupPath == .cleanupUnproven)
    #expect(report.stopOutcome == .timeout)
    #expect(report.emergencyStopOutcome == .timeout)
    #expect(!report.cleanupVerified)
    #expect(trace.count("stop") == 0)
    #expect(trace.count("emergency_stop") == 0)
  }

  @Test func lateRejectedAcquisitionDoesNotChargeAbsentCleanupStages() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in
          ProductM2AuthorizationAttempt(
            source: .nativePortal,
            operation: {
              clock.set(milliseconds: 80_000)
              return .rejected(
                source: .nativePortal,
                failure: .timedOut,
                cleanup: ProductM2AuthorizationCloseReceipt(
                  outcome: .accepted,
                  ownedMaterialErased: true,
                  sourceCloseRequested: true,
                  serverContactRequested: true
                )
              )
            },
            cancel: {}
          )
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(report.cleanupVerified)
    #expect(report.cleanupPath == .notRequired)
    #expect(report.authorizationClose == .accepted)
    #expect(report.authorizationOwnedMaterialErased)
    #expect(!report.helperMutationRequested)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("verify") == 1)
  }
}

enum ProductM2LateCleanupStage: CaseIterable, Sendable {
  case control
  case authorization
  case verification
}

private final class ProductM2StopTimeoutRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [Int] = []

  func record(_ timeout: Int) {
    lock.withLock { storage.append(timeout) }
  }

  var values: [Int] {
    lock.withLock { storage }
  }
}
