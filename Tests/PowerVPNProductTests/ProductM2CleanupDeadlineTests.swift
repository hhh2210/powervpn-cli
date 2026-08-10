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
