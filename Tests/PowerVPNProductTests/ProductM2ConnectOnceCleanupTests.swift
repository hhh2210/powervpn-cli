import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2ConnectOnceCleanupTests {
  @Test func sentStartWithoutLeaseAndSingleExitNeverEmergencyStops() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: .noLease(generation: m2ExitedGeneration)
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .startRejected)
    #expect(report.cleanupPath == .naturalHelperExit)
    #expect(report.emergencyStopOutcome == .notAttempted)
    #expect(report.cleanupVerified)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("ssh") == 0)
    #expect(trace.count("logout") == 1)
  }

  @Test func sentStartWithoutLeaseAndExactRunningUsesOneEmergencyStop() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: .noLease(generation: m2RunningGeneration)
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .startRejected)
    #expect(report.cleanupPath == .authenticatedEmergencyStop)
    #expect(report.emergencyStopOutcome == .transportAcknowledged)
    #expect(report.cleanupVerified)
    #expect(trace.count("emergency_stop") == 1)
    #expect(trace.count("stop") == 0)
    #expect(trace.count("ssh") == 0)
  }

  @Test func changedPostStartGenerationIsUnprovenAndNeverStops() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: .noLease(generation: m2UnavailableGeneration)
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.cleanupPath == .cleanupUnproven)
    #expect(!report.cleanupVerified)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("stop") == 0)
    #expect(trace.count("logout") == 1)
  }

  @Test func stopAcknowledgementCannotOverrideOneFailedCleanupDimension() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let incomplete = ProductM2CleanupEvidence(
      defaultRouteRestored: true,
      dnsRestored: true,
      interfacesRestored: true,
      utunRestored: true,
      selectedRouteResidueCount: 1,
      surgeStateRestored: true,
      helperGenerationRestored: true
    )
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      cleanup: incomplete
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.outcome == .cleanupUnproven)
    #expect(report.firstBadEvent == .cleanupVerificationRejected)
    #expect(!report.cleanupVerified)
    #expect(report.finalState == .failed)
  }

  @Test func unsentLeaseStopWithExactRunningUsesOneEmergencyStop() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: false)
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.cleanupPath == .authenticatedEmergencyStop)
    #expect(report.emergencyStopOutcome == .transportAcknowledged)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 1)
  }

  @Test func sentLeaseStopFailureNeverRetriesWithEmergencyStop() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true)
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.emergencyStopOutcome == .notAttempted)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
  }

  @Test func cancellationAfterAcquisitionStillLogsOutAndVerifies() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let first = ProductM2NetworkBaseline()
    let trace = ProductM2TestTrace(baselines: [first])
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cancelDuringAcquire: true
      ))

    let report = await Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )
    }.value

    #expect(report.outcome == .cancelled)
    #expect(report.cleanupVerified)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 1)
    #expect(trace.verifiedBaselineID == first.identifier)
  }

  @Test func cancellationDuringSSHStillStopsLogsOutAndVerifies() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cancelDuringSSH: true
      ))

    let report = await Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )
    }.value

    #expect(report.outcome == .cancelled)
    #expect(report.sshProof == .proven)
    #expect(report.sshProofEvidence?.outcome == .proven)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.cleanupVerified)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 1)
  }

  @Test(arguments: [PortalLeaseLogoutStatus.timedOut, .alreadyClosed])
  func nonAcceptedPortalLogoutMakesCleanupUnproven(
    _ logout: PortalLeaseLogoutStatus
  ) async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        logout: logout
      ))

    let report = await coordinator.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.authorizationClose != .accepted)
    #expect(report.outcome == .cleanupUnproven)
    #expect(report.firstBadEvent == .authorizationCloseRejected)
    #expect(!report.cleanupVerified)
  }
}
