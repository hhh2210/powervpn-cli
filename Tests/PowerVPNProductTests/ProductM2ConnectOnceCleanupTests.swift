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
    #expect(trace.count("stop") == 1)
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
    #expect(trace.count("stop") == 1)
    #expect(trace.count("ssh") == 0)
  }

  @Test func changedPostStartGenerationIsUnprovenAfterOneStopAttempt() async throws {
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
    #expect(trace.count("stop") == 1)
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

  @Test func structuralRouteDifferenceCannotBeReportedAsVerifiedCleanup() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let evidence = ProductM2CleanupEvidence(
      defaultRouteRestored: true,
      dnsRestored: true,
      interfacesRestored: true,
      utunRestored: true,
      surgeStateRestored: true,
      helperGenerationRestored: true,
      structuralRouteTablesEqual: false
    )
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      cleanup: evidence
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(!report.cleanupEvidence.structuralRouteTablesEqual)
    #expect(!report.cleanupVerified)
    #expect(report.outcome == .cleanupUnproven)
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

  @Test func cancellationDuringActiveCaptureCannotOverwriteSSHOrCleanup() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cancelDuringActiveCapture: true
      ))

    let report = await Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )
    }.value

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.firstBadEvent == nil)
    #expect(report.sshProof == .proven)
    #expect(report.networkProofSource == .sshBanner)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.cleanupVerified)
    let events = trace.events
    #expect(m2EventIndex("ssh", in: events) < (events.lastIndex(of: "baseline") ?? 0))
    #expect((events.lastIndex(of: "baseline") ?? .max) < m2EventIndex("stop", in: events))
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 1)
  }

  @Test(arguments: [ProductM2AuthorizationCloseOutcome.timedOut, .alreadyClosed])
  func nonAcceptedPortalLogoutMakesCleanupUnproven(
    _ logout: ProductM2AuthorizationCloseOutcome
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

  @Test func acknowledgedStopNeedsNoInvalidityClassification() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.stopInvalidityClass == nil)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("observe_generation") == 4)
  }

  @Test func invalidStopClassifiesSingleHelperExitWithOneBoundedObservation() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true),
        onStop: { _ in trace.setGeneration(m2ExitedGeneration) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.stopInvalidityClass == .helperExitedSingleGeneration)
    let events = trace.events
    let lastObserve = events.lastIndex(of: "observe_generation") ?? 0
    #expect(m2EventIndex("stop", in: events) < lastObserve)
    #expect(trace.count("begin_start") == 1)
    #expect(trace.count("mutation_lease") == 1)
    #expect(trace.count("observe_generation") == 5)
  }

  @Test func invalidStopWithSameRunningGenerationClassifiesSessionInvalid() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true)
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.stopInvalidityClass == .helperRunningSessionInvalid)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("observe_generation") == 5)
  }

  @Test func invalidStopWithAdvancedRunCountClassifiesHelperRestart() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true),
        onStop: { _ in trace.setGeneration(m2RestartedGeneration) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.stopInvalidityClass == .helperRestarted)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("observe_generation") == 5)
  }

  @Test func invalidStopWithUnobservableGenerationStaysUnclassified() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true),
        onStop: { _ in trace.setGeneration(m2UnavailableGeneration) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.stopInvalidityClass == .unclassified)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("observe_generation") == 5)
  }

  @Test func unsentInvalidStopClassifiesFromExistingObservation() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: false)
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.cleanupPath == .authenticatedEmergencyStop)
    #expect(report.stopInvalidityClass == .helperRunningSessionInvalid)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 1)
  }

  @Test func invalidStopClassificationSurvivesDeadlineInvalidatedRebuild() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledgedStop(outcome: .connectionInvalid, requestSent: true),
        onStop: { _ in
          // The stop completes but consumes the control-cleanup stage, so the
          // runner rebuilds the control cleanup via invalidatedByDeadline.
          clock.set(milliseconds: 73_001)
          trace.setGeneration(m2ExitedGeneration)
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: .start(clock: clock.clock)
    )

    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.cleanupPath == .cleanupUnproven)
    #expect(!report.cleanupVerified)
    #expect(report.outcome == .cleanupUnproven)
    // The classification computed before the deadline invalidation must
    // survive the ControlCleanup rebuild.
    #expect(report.stopInvalidityClass == .helperExitedSingleGeneration)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    // Classification spent exactly the one bounded read-only observation
    // (report-budget fallback), and nothing else mutated afterwards.
    #expect(trace.count("observe_generation") == 5)
    #expect(trace.count("mutation_lease") == 1)
    #expect(trace.count("begin_start") == 1)
  }
}
