import Foundation
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
    #expect(report.networkProofSource == ProductM2NetworkProofSource.none)
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

  @Test func ineffectiveSelectedRouteBindingIsDiagnosticAndSSHStillDecides() async throws {
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

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.firstBadEvent == nil)
    #expect(report.vendorStatusEvidence.connectedProven)
    #expect(report.activeNetworkEvidence.selectedRouteBindingDeltaCount == 1)
    #expect(!report.activeNetworkEvidence.effectiveSelectedRouteBindingIntroduced)
    #expect(report.activeNetworkEvidence.selectedResourcePathProven)
    #expect(!report.activeNetworkEvidence.connectionProven)
    #expect(report.sshProof == .proven)
    #expect(report.networkProofSource == .sshBanner)
    #expect(trace.count("baseline") == 3)
    #expect(trace.count("active_assessment") == 1)
    #expect(trace.count("ssh") == 1)
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
    #expect(report.networkProofSource == .sshBanner)
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

  @Test func captureOutcomeMapsObserverStatesFaithfully() {
    // Complete snapshot: baseline flows through with the measured-complete token.
    let complete = ProductM2ActiveCaptureOutcome(snapshot: m2CaptureSnapshotFixture())
    #expect(complete.state == .measuredComplete)
    #expect(complete.baseline != nil)
    #expect(complete.changeAxes.isEmpty)
    #expect(complete.incompleteReason == nil)

    // Helper A≠B during capture: change axis is the helper generation.
    let helperChanged = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        helperObservationState: .changedDuringCapture,
        vendorProcesses: m2VendorProcessesFixture(charonProcessCount: 1)
      ))
    #expect(helperChanged.baseline == nil)
    #expect(helperChanged.state == .changedDuringCapture)
    #expect(helperChanged.changeAxes == [.helperGeneration])
    #expect(helperChanged.incompleteReason == nil)

    // Everything measured, helper generation exact, but the active-state vendor
    // process-set rule cannot pass: structural rejection, no change axis.
    let charonMismatch = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        vendorProcesses: m2VendorProcessesFixture()
      ))
    #expect(charonMismatch.state == .measuredIncomplete)
    #expect(charonMismatch.changeAxes.isEmpty)
    #expect(charonMismatch.incompleteReason == .vendorProcessesInconsistent)

    let ipsecPresent = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        vendorProcesses: m2VendorProcessesFixture(ipsecProcessCount: 1)
      ))
    #expect(ipsecPresent.state == .measuredIncomplete)
    #expect(ipsecPresent.incompleteReason == .vendorProcessesInconsistent)

    // Fully measured but the helper generation itself is not exact.
    let generationNotExact = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(helperGeneration: m2UnavailableGeneration))
    #expect(generationNotExact.state == .measuredIncomplete)
    #expect(generationNotExact.incompleteReason == .generationNotExact)

    // A failed sub-observation maps its observer state token verbatim.
    let commandFailed = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        defaultRoute: .unavailable(.commandFailed)))
    #expect(commandFailed.state == .commandFailed)
    #expect(commandFailed.changeAxes == [.defaultRoute])
    #expect(commandFailed.incompleteReason == .subobservationFailed)
  }

  @Test func helperChangedCaptureIsDiagnosticWhenSSHProvesNetwork() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let capture = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        helperObservationState: .changedDuringCapture,
        vendorProcesses: m2VendorProcessesFixture(charonProcessCount: 1)
      ))

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        activeCaptureOutcome: capture
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.firstBadEvent == nil)
    #expect(report.activeNetworkEvidence == .unavailable)
    #expect(report.activeCaptureState == .changedDuringCapture)
    #expect(report.activeCaptureChangeAxes == [.helperGeneration])
    #expect(report.activeCaptureIncompleteReason == nil)
    #expect(report.sshProof == .proven)
    #expect(report.networkProofSource == .sshBanner)
    #expect(trace.count("active_assessment") == 0)
    #expect(trace.count("ssh") == 1)
    #expect(trace.count("stop") == 1)
    #expect(report.cleanupVerified)
  }

  @Test func structuralVendorProcessRejectionReportsDistinctTokens() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let capture = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        vendorProcesses: m2VendorProcessesFixture()
      ))

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        activeCaptureOutcome: capture
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.firstBadEvent == nil)
    #expect(report.activeNetworkEvidence == .unavailable)
    #expect(report.activeCaptureState == .measuredIncomplete)
    #expect(report.activeCaptureChangeAxes == nil)
    #expect(report.activeCaptureIncompleteReason == .vendorProcessesInconsistent)
    #expect(report.sshProof == .proven)
    #expect(report.networkProofSource == .sshBanner)
  }

  @Test func sshFailureReportsBothProofStateAndCaptureClassification() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let capture = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        vendorProcesses: m2VendorProcessesFixture()
      ))

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        sshProof: .rejected,
        activeCaptureOutcome: capture
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .sshProofRejected)
    #expect(report.firstBadEvent == .sshProofRejected)
    #expect(report.sshProof == .rejected)
    #expect(report.sshProofEvidence?.outcome == .rejected)
    #expect(report.activeCaptureState == .measuredIncomplete)
    #expect(report.activeCaptureIncompleteReason == .vendorProcessesInconsistent)
    #expect(report.activeNetworkEvidence == .unavailable)
    #expect(report.networkProofSource == ProductM2NetworkProofSource.none)
    #expect(trace.count("ssh") == 1)
    #expect(
      m2EventIndex("ssh", in: trace.events)
        < (trace.events.lastIndex(of: "baseline") ?? 0)
    )
    #expect(report.cleanupVerified)
  }

  @Test func measuredCompleteCaptureKeepsExistingSuccessShape() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        activeCaptureOutcome: ProductM2ActiveCaptureOutcome(
          snapshot: m2CaptureSnapshotFixture(
            helperGeneration: m2ColdGeneration,
            vendorProcesses: m2VendorProcessesFixture()
          ))
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.activeNetworkEvidence.connectionProven)
    #expect(report.activeCaptureState == .measuredComplete)
    #expect(report.activeCaptureChangeAxes == nil)
    #expect(report.activeCaptureIncompleteReason == nil)
    #expect(report.sshProof == .proven)
    #expect(report.networkProofSource == .sshBanner)
  }

  @Test func vendorStatusFailureBeforeCaptureReportsNotAttempted() async throws {
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
    #expect(report.activeCaptureState == .notAttempted)
    #expect(report.activeCaptureChangeAxes == nil)
    #expect(report.activeCaptureIncompleteReason == nil)
    #expect(report.stopInvalidityClass == nil)
    #expect(report.networkProofSource == ProductM2NetworkProofSource.none)
  }

  @Test func classificationFieldsAreOmittedWhenNilAndStayValueFree() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let capture = ProductM2ActiveCaptureOutcome(
      snapshot: m2CaptureSnapshotFixture(
        helperGeneration: m2RunningGeneration,
        helperObservationState: .changedDuringCapture,
        vendorProcesses: m2VendorProcessesFixture(charonProcessCount: 1)
      ))

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        activeCaptureOutcome: capture
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )
    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.networkProofSource == .sshBanner)
    let successFixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML(["Campus NC"]))
    defer { successFixture.erase() }
    let success = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: successFixture.snapshot,
        trace: ProductM2TestTrace()
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )
    let encodedSuccess = try #require(
      String(bytes: JSONEncoder().encode(success), encoding: .utf8))
    #expect(encodedSuccess.contains("\"activeCaptureState\":\"measured_complete\""))
    #expect(encodedSuccess.contains("\"networkProofSource\":\"ssh_banner\""))
    #expect(!encodedSuccess.contains("activeCaptureChangeAxes"))
    #expect(!encodedSuccess.contains("activeCaptureIncompleteReason"))
    #expect(!encodedSuccess.contains("stopInvalidityClass"))
    #expect(!encodedSuccess.contains("com.leadsec"))
    #expect(!encodedSuccess.contains("aaaa"))

    let startFailureFixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML(["Campus NC"]))
    defer { startFailureFixture.erase() }
    let startFailure = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: startFailureFixture.snapshot,
        trace: ProductM2TestTrace(),
        plan: .preSubmissionFailure
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )
    #expect(startFailure.outcome == .startRejected)
    #expect(startFailure.networkProofSource == nil)
    let encodedStartFailure = try #require(
      String(bytes: JSONEncoder().encode(startFailure), encoding: .utf8))
    #expect(!encodedStartFailure.contains("networkProofSource"))
    #expect(!encodedStartFailure.contains("activeCaptureState"))
    let described = String(describing: report)
    #expect(described.contains("sshBanner"))
    #expect(!described.contains("com.leadsec"))
    #expect(!described.contains("aaaa"))
  }
}
