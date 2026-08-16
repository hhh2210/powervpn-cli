import Foundation
import Testing

@testable import PowerVPNCore
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
    let active = ProductM2NetworkBaseline()
    let trace = ProductM2TestTrace(baselines: [first, second, active])
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
    #expect(report.authorizationSource == .nativePortal)
    #expect(report.authorizationAcquisition == .acquired)
    #expect(report.authorizationFailure == nil)
    #expect(report.startOutcome == .transportAcknowledged)
    #expect(report.vendorStatusEvidence.connectedProven)
    #expect(report.routeActivationOutcome == .transportAcknowledged)
    #expect(report.routeActivationRequestSent)
    #expect(report.routeActivationAcknowledged)
    #expect(report.routeActivationPeerGenerationValidated)
    #expect(report.activeNetworkEvidence.connectionProven)
    #expect(report.sshProof == .proven)
    #expect(report.networkProofSource == .sshBanner)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.routeDeactivationOutcome == .transportAcknowledged)
    #expect(report.routeDeactivationRequestSent)
    #expect(report.routeDeactivationAcknowledged)
    #expect(report.routeDeactivationPeerGenerationValidated)
    #expect(report.authorizationClose == .accepted)
    #expect(report.cleanupVerified)
    #expect(trace.count("baseline") == 3)
    #expect(trace.count("preflight") == 2)
    #expect(trace.verifiedBaselineID == second.identifier)
    #expect(Set(trace.networkWindowIDs).count == 1)
    #expect(trace.matcherPresence == [false, true, true, true])
    #expect(trace.cleanupStartSent == [true])
    #expect(report.sshProofEvidence?.outcome == report.sshProof)
    let events = trace.events
    #expect(m2EventIndex("preflight", in: events) < m2EventIndex("acquire", in: events))
    #expect(m2EventIndex("acquire", in: events) < m2EventIndex("baseline_stable", in: events))
    #expect(m2EventIndex("baseline_stable", in: events) < m2EventIndex("begin_start", in: events))
    #expect(m2EventIndex("begin_start", in: events) < m2EventIndex("status_wait", in: events))
    #expect(m2EventIndex("status_wait", in: events) < m2EventIndex("route_enable", in: events))
    #expect(m2EventIndex("route_enable", in: events) < m2EventIndex("ssh", in: events))
    #expect(m2EventIndex("ssh", in: events) < m2EventIndex("active_assessment", in: events))
    #expect(
      m2EventIndex("active_assessment", in: events)
        < m2EventIndex("route_disable", in: events))
    #expect(m2EventIndex("route_disable", in: events) < m2EventIndex("stop", in: events))
    #expect(m2EventIndex("stop", in: events) < m2EventIndex("logout", in: events))
    #expect(m2EventIndex("logout", in: events) < m2EventIndex("verify", in: events))
  }

  @Test func routeActivationRejectionFailsBeforeSSHAndStillCleansUp() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        routeActivationOutcome: .helperRejected
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .routeActivationRejected)
    #expect(report.firstBadEvent == .routeActivationRejected)
    #expect(report.routeActivationOutcome == .helperRejected)
    #expect(report.routeActivationRequestSent)
    #expect(!report.routeActivationAcknowledged)
    #expect(trace.count("route_enable") == 1)
    #expect(trace.count("ssh") == 0)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("verify") == 1)
    #expect(report.cleanupVerified)
  }

  @Test func routeDeactivationFailureStillRunsStopAndAuthoritativeCleanup() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        routeDeactivationOutcome: .connectionInvalid
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.routeDeactivationOutcome == .connectionInvalid)
    #expect(report.routeDeactivationRequestSent)
    #expect(!report.routeDeactivationAcknowledged)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("verify") == 1)
    #expect(report.cleanupVerified)
    #expect(
      m2EventIndex("route_disable", in: trace.events)
        < m2EventIndex("stop", in: trace.events))
  }

  @Test func coldToFirstObservedBaselineGenerationDriftNeverAcquiresPortal() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace(
      baselines: [m2ObservedNetworkBaseline(generation: m2RunningGeneration)]
    )
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
    #expect(report.finalState == .blocked)
    #expect(trace.count("baseline") == 1)
    #expect(trace.count("acquire") == 0)
    #expect(trace.count("begin_start") == 0)
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

  @Test func explicitSecondChildWithEqualSiblingRoutesSelectsUniquely() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2SingleResourceMultiTunnelXML(["Campus First", "Campus Second"])
    )
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus Second", sshTarget: .thu21)
    )

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(trace.count("begin_start") == 1)
    #expect(trace.matcherPresence == [false, true, true, true])
  }

  @Test func duplicateChildDisplayNamesRemainAmbiguous() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2SingleResourceMultiTunnelXML(["Campus NC", "Campus NC"])
    )
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .resourceAmbiguous)
    #expect(trace.count("begin_start") == 0)
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

  @Test func controlReceiptMapsWireDiagnosticsOnlyForStartOperation() {
    let start = ProductM2ControlReceipt(
      vendorDiagnosticReceipt(operation: .startConnection)
    )
    #expect(
      start.startEventSignatures
        == ["1:connection:get_tun_name_success:bool,namev4:string"])
    #expect(start.startReplySignatures == ["2:reply:{}"])
    #expect(start.unexpectedEventSignature == ["mystery:string"])

    let stop = ProductM2ControlReceipt(
      vendorDiagnosticReceipt(operation: .stopConnection)
    )
    #expect(stop.startEventSignatures == nil)
    #expect(stop.startReplySignatures == nil)
    #expect(stop.unexpectedEventSignature == nil)
  }

  @Test func startWireDiagnosticsFlowToSchemaFourteenReportWithoutValues() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .submittedFailure(.unexpectedConnectionEvent),
        startEventSignatures: [
          "1:connection:get_tun_name_success:bool,namev4:string",
          "2:connection:mystery:string",
        ],
        startReplySignatures: ["3:reply:{}"],
        unexpectedEventSignature: ["mystery:string"]
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.schemaVersion == 14)
    #expect(
      report.startEventSignatures == [
        "1:connection:get_tun_name_success:bool,namev4:string",
        "2:connection:mystery:string",
      ])
    #expect(report.startReplySignatures == ["3:reply:{}"])
    #expect(report.unexpectedEventSignature == ["mystery:string"])
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
    #expect(json.contains("\"startEventSignatures\""))
    #expect(json.contains("\"startReplySignatures\""))
    #expect(json.contains("\"unexpectedEventSignature\""))
    #expect(!json.contains("utun-value-must-not-escape"))
    #expect(!json.contains("rejected-value-must-not-escape"))
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
    #expect(json.contains("\"authorizationOwnedMaterialErased\":true"))
    #expect(json.contains("\"schemaVersion\":14"))
    #expect(json.contains("\"routeActivationOutcome\":\"transport_acknowledged\""))
    #expect(json.contains("\"routeActivationAcknowledged\":true"))
    #expect(json.contains("\"routeDeactivationOutcome\":\"transport_acknowledged\""))
    #expect(json.contains("\"routeDeactivationAcknowledged\":true"))
    #expect(!json.contains("portal:"))
    #expect(!json.contains("helper-session-material"))
    #expect(!json.contains("psk-material"))
    #expect(!json.contains("166.111.143.19"))
    #expect(!json.contains("10.1.2.3"))
    #expect(!json.contains("11.11.0.0"))
    #expect(!json.contains("\"handle\""))
    #expect(!json.contains("tunnel-name"))
    #expect(!json.contains("updown_nc"))
    #expect(json.contains("\"persistentRoutesRestored\":true"))
    #expect(json.contains("\"selectedRouteResidueCount\":0"))
    #expect(json.contains("\"containsRawRoutes\":false"))
    #expect(report.startEventSignatures == nil)
    #expect(report.startReplySignatures == nil)
    #expect(report.unexpectedEventSignature == nil)
    #expect(!json.contains("\"startEventSignatures\""))
    #expect(!json.contains("\"startReplySignatures\""))
    #expect(!json.contains("\"unexpectedEventSignature\""))
  }
}

private func vendorDiagnosticReceipt(
  operation: VendorCharonControlOperation
) -> VendorCharonControlReceipt {
  VendorCharonControlReceipt(
    operation: operation,
    outcome: .unexpectedConnectionEvent,
    requestSent: true,
    emptyReplyObserved: false,
    peerGenerationValidated: false,
    connectionRetained: false,
    connectionCancelRequested: true,
    encodingError: nil,
    statusEventCount: 0,
    dispatcherTailEventCount: 0,
    incomingEventSignatures: [
      "1:connection:get_tun_name_success:bool,namev4:string"
    ],
    replySignatures: ["2:reply:{}"],
    unexpectedEventSignature: ["mystery:string"]
  )
}
