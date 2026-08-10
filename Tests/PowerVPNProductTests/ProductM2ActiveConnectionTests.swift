import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2ActiveConnectionTests {
  @Test func statusTimeoutNeverCapturesActiveNetworkOrRunsSSH() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let status = ProductM2VendorStatusEvidence(
      outcome: .timeout,
      statusEventCount: 0,
      latestClassification: nil,
      terminalControlOutcome: nil
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledged(status: status)
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .vendorStatusUnproven)
    #expect(report.firstBadEvent == .vendorStatusUnproven)
    #expect(report.vendorStatusEvidence.outcome == .timeout)
    #expect(!report.vendorStatusEvidence.connectedProven)
    #expect(!report.activeNetworkEvidence.selectedResourcePathProven)
    #expect(trace.count("baseline") == 2)
    #expect(trace.count("active_assessment") == 0)
    #expect(trace.count("ssh") == 0)
    #expect(trace.count("stop") == 1)
    #expect(report.cleanupVerified)
  }

  @Test func inconsistentConnectedStatusIsNotPromoted() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let inconsistent = ProductM2VendorStatusEvidence(
      outcome: .connected,
      statusEventCount: 0,
      latestClassification: .connected,
      terminalControlOutcome: nil
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledged(status: inconsistent)
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .vendorStatusUnproven)
    #expect(!report.vendorStatusEvidence.connectedProven)
    #expect(trace.count("active_assessment") == 0)
    #expect(trace.count("ssh") == 0)
  }

  @Test func ineffectiveSelectedRouteBindingNeverRunsSSH() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let unproven = ProductM2ActiveNetworkEvidence(
      complete: true,
      helperSingleRunningGeneration: true,
      surgeStable: true,
      vendorGUIAbsent: true,
      unrelatedVendorHelpersAbsent: true,
      selectedRouteBindingDeltaCount: 1,
      effectiveSelectedRouteBindingIntroduced: false,
      newUtunCount: 1,
      defaultRouteChanged: false,
      dnsChanged: false,
      persistentRoutesChanged: false,
      selectedResourcePathProven: true
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        activeNetwork: unproven
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .activeNetworkUnproven)
    #expect(report.firstBadEvent == .activeNetworkUnproven)
    #expect(report.vendorStatusEvidence.connectedProven)
    #expect(report.activeNetworkEvidence.selectedRouteBindingDeltaCount == 1)
    #expect(!report.activeNetworkEvidence.effectiveSelectedRouteBindingIntroduced)
    #expect(report.activeNetworkEvidence.selectedResourcePathProven)
    #expect(!report.activeNetworkEvidence.connectionProven)
    #expect(trace.count("baseline") == 3)
    #expect(trace.count("active_assessment") == 1)
    #expect(trace.count("ssh") == 0)
    #expect(trace.count("stop") == 1)
    #expect(report.cleanupVerified)
  }

  @Test func disconnectBetweenSSHAndStopCannotPublishConnectedSuccess() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .acknowledged(stopStatus: .disconnected)
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .vendorStatusUnproven)
    #expect(report.firstBadEvent == .vendorStatusUnproven)
    #expect(report.lastGoodState == .connecting)
    #expect(report.sshProof == .proven)
    #expect(report.vendorStatusEvidence.outcome == .disconnected)
    #expect(report.vendorStatusEvidence.latestClassification == .disconnected)
    #expect(!report.vendorStatusEvidence.connectedProven)
    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.cleanupVerified)
    #expect(trace.count("ssh") == 1)
    #expect(trace.count("stop") == 1)
    #expect(m2EventIndex("ssh", in: trace.events) < m2EventIndex("stop", in: trace.events))
  }
}
