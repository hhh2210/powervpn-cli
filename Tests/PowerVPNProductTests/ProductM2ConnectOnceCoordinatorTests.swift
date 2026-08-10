import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2ConnectOnceCoordinatorTests {
  @Test func rejectedSessionRuntimePreflightRunsBeforeTTYOrBaseline() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        controlRuntimePreflightAccepted: false
      ))

    let report = await coordinator.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .preflightBlocked)
    #expect(trace.events == ["session_preflight"])
    #expect(trace.count("baseline") == 0)
    #expect(trace.count("acquire") == 0)
    #expect(trace.count("begin_start") == 0)
  }

  @Test func successfulRunUsesSecondBaselineAndSameLeaseCleanup() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let first = ProductM2NetworkBaseline()
    let second = ProductM2NetworkBaseline()
    let trace = ProductM2TestTrace(baselines: [first, second])
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace
      ))

    let report = await coordinator.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.finalState == .disconnected)
    #expect(report.lastGoodState == .connected)
    #expect(report.firstBadEvent == nil)
    #expect(report.startOutcome == .transportAcknowledged)
    #expect(report.sshProof == .proven)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.portalLogout == .accepted)
    #expect(report.cleanupVerified)
    #expect(trace.count("baseline") == 2)
    #expect(trace.count("preflight") == 2)
    #expect(trace.verifiedBaselineID == second.identifier)
    #expect(Set(trace.networkWindowIDs).count == 1)
    #expect(trace.matcherPresence == [false, true, true])
    #expect(trace.cleanupStartSent == [true])
    #expect(report.sshProofEvidence?.outcome == report.sshProof)
    let events = trace.events
    #expect(m2EventIndex("preflight", in: events) < m2EventIndex("acquire", in: events))
    #expect(m2EventIndex("acquire", in: events) < m2EventIndex("baseline_stable", in: events))
    #expect(m2EventIndex("baseline_stable", in: events) < m2EventIndex("begin_start", in: events))
    #expect(m2EventIndex("begin_start", in: events) < m2EventIndex("ssh", in: events))
    #expect(m2EventIndex("ssh", in: events) < m2EventIndex("stop", in: events))
    #expect(m2EventIndex("stop", in: events) < m2EventIndex("logout", in: events))
    #expect(m2EventIndex("logout", in: events) < m2EventIndex("verify", in: events))
  }

  @Test func baselineDriftAfterPortalAcquisitionSendsNoStart() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let first = ProductM2NetworkBaseline()
    let second = ProductM2NetworkBaseline()
    let trace = ProductM2TestTrace(baselines: [first, second])
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        baselineStable: false
      ))

    let report = await coordinator.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .networkBaselineChanged)
    #expect(report.firstBadEvent == .networkBaselineChanged)
    #expect(report.finalState == .blocked)
    #expect(report.cleanupVerified)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("logout") == 1)
    #expect(trace.verifiedBaselineID == second.identifier)
    #expect(Set(trace.networkWindowIDs).count == 1)
    #expect(trace.matcherPresence == [false, true, true])
    #expect(trace.cleanupStartSent == [false])
  }

  @Test func zeroOrMultipleExactDisplayNameMatchesNeverTouchControl() async throws {
    let cases: [([String], ProductM2ConnectOutcome)] = [
      (["Other NC"], .resourceNotFound),
      (["Campus NC", "Campus NC"], .resourceAmbiguous),
    ]
    for (names, outcome) in cases {
      let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(names))
      let trace = ProductM2TestTrace()
      let coordinator = ProductM2ConnectOnceCoordinator(
        dependencies: productM2TestDependencies(
          snapshot: fixture.snapshot,
          trace: trace
        ))

      let report = await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )

      #expect(report.outcome == outcome)
      #expect(trace.count("begin_start") == 0)
      #expect(trace.count("emergency_stop") == 0)
      #expect(trace.count("logout") == 1)
      fixture.erase()
    }
  }

  @Test func secondPreflightFailureAfterStableBaselineSendsNoStart() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace(preflightResults: [true, false])
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace
      ))

    let report = await coordinator.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .generationFenceRejected)
    #expect(report.firstBadEvent == .generationFenceRejected)
    #expect(trace.count("preflight") == 2)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("logout") == 1)
  }

  @Test func transportAcknowledgementWithoutSSHProofIsNeverConnected() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        sshProof: .rejected
      ))

    let report = await coordinator.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu52)
    )

    #expect(report.outcome == .sshProofRejected)
    #expect(report.lastGoodState == .connecting)
    #expect(report.sshProof == .rejected)
    #expect(report.finalState == .disconnected)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
  }

  @Test func proofForDifferentLockedTargetIsNormalizedToRejection() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        sshEvidenceTarget: .thu52
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .sshProofRejected)
    #expect(report.sshProof == .rejected)
    #expect(report.sshProofEvidence?.outcome == .rejected)
    #expect(report.sshProofEvidence?.target == .thu52)
    #expect(report.lastGoodState == .connecting)
  }

  @Test func selectedRouteThatMissesLockedTargetFailsBeforeSecondBaseline() async throws {
    let xml = m2ResourceXML(["Campus NC"])
      .replacingOccurrences(of: "11.11.0.0/16", with: "10.1.2.0/24")
    let fixture = try authenticatedSnapshot(resourceXML: xml)
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .selectedRouteCoverageRejected)
    #expect(report.firstBadEvent == .selectedRouteCoverageRejected)
    #expect(trace.count("baseline") == 1)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("ssh") == 0)
    #expect(trace.matcherPresence == [false, false])
  }

  @Test func unsupportedRouteFamilyIsSnapshotRejectionNotCoverageRejection() async throws {
    let xml = m2ResourceXML(["Campus NC"])
      .replacingOccurrences(of: "family=\"4\"", with: "family=\"6\"")
    let fixture = try authenticatedSnapshot(resourceXML: xml)
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .startSnapshotRejected)
    #expect(report.firstBadEvent == .startSnapshotRejected)
    #expect(trace.count("baseline") == 1)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("ssh") == 0)
  }

  @Test func encodedReportContainsNoHandleOrProtocolMaterial() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)

    #expect(json.contains("\"containsSecrets\":false"))
    #expect(json.contains("\"snapshotSerialized\":false"))
    #expect(!json.contains("portal:"))
    #expect(!json.contains("helper-session-material"))
    #expect(!json.contains("psk-material"))
    #expect(!json.contains("166.111.143.19"))
    #expect(!json.contains("10.1.2.3"))
    #expect(!json.contains("11.11.0.0"))
    #expect(!json.contains("\"handle\""))
    #expect(json.contains("\"persistentRoutesRestored\":true"))
    #expect(json.contains("\"selectedRouteResidueCount\":0"))
    #expect(json.contains("\"containsRawRoutes\":false"))
  }
}
