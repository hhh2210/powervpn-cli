import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorXPCReachabilityProbeTests {
  @Test func fixedContractHasNoCallerControlledServiceOrPayload() {
    #expect(VendorXPCSessionContract.serviceName == "com.leadsec.charon-xpc")
    #expect(
      VendorXPCGetVersionRequestContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "get_version"),
      ])
  }

  @Test func strictReplyAndGenerationFenceAreReachable() async {
    let before = generation(running: false, pid: nil, runs: 10)
    let during = generation(running: true, pid: 400, runs: 11)
    let after = generation(running: false, pid: nil, runs: 11)
    let observer = ProbeGenerationObserver([before, during, after])
    let transport = ProbeTransport(evidence: acceptedEvidence(), peerPID: 400)

    let result = await makeProbe(
      transport: transport,
      observer: observer
    ).probe(timeoutMilliseconds: 500)

    #expect(result.status == .reachable)
    #expect(result.probePerformed)
    #expect(result.transportAccepted)
    #expect(result.helperGenerationRelation == .launchedAndExited)
    #expect(result.finalGeneration == after)
    #expect(result.connectionCancelRequested)
    #expect(await transport.callCount == 1)
    #expect(await observer.callCount == 3)
  }

  @Test func preflightBlockReturnsLatestGenerationWithoutTransport() async {
    let before = generation(running: false, pid: nil, runs: 8)
    let observer = ProbeGenerationObserver([before])
    let transport = ProbeTransport(evidence: acceptedEvidence(), peerPID: 400)

    let result = await makeProbe(
      transport: transport,
      observer: observer,
      preflight: blockedPreflight()
    ).probe(timeoutMilliseconds: 500)

    #expect(result.status == .preflightBlocked)
    #expect(!result.probePerformed)
    #expect(!result.transportAccepted)
    #expect(result.helperGenerationRelation == .inactive)
    #expect(result.finalGeneration == before)
    #expect(!result.connectionCancelRequested)
    #expect(await transport.callCount == 0)
    #expect(await observer.callCount == 1)
  }

  @Test func invalidTimeoutRunsNoObservationPreflightOrTransport() async {
    let observer = ProbeGenerationObserver([generation(running: false, pid: nil, runs: 2)])
    let transport = ProbeTransport(evidence: acceptedEvidence(), peerPID: 400)
    let preflight = ProbePreflightChecker(safePreflight())
    let probe = VendorXPCReachabilityProbe(
      transport: transport,
      generationObserver: observer,
      preflightChecker: preflight
    )

    let result = await probe.probe(timeoutMilliseconds: 0)

    #expect(result.status == .invalidTimeout)
    #expect(!result.probePerformed)
    #expect(result.finalGeneration == .unavailable)
    #expect(await observer.callCount == 0)
    #expect(await preflight.callCount == 0)
    #expect(await transport.callCount == 0)
  }

  @Test func exactReplyWithoutFinalGenerationFenceIsUnreachable() async {
    let before = generation(running: false, pid: nil, runs: 10)
    let unchanged = generation(running: false, pid: nil, runs: 10)
    let observer = ProbeGenerationObserver([before, unchanged])
    let transport = ProbeTransport(
      evidence: acceptedEvidence(peerValidated: true),
      peerPID: nil
    )

    let result = await makeProbe(
      transport: transport,
      observer: observer
    ).probe(timeoutMilliseconds: 500)

    #expect(result.status == .unreachable)
    #expect(result.probePerformed)
    #expect(result.transportAccepted)
    #expect(result.helperGenerationRelation == .inactive)
    #expect(result.finalGeneration == unchanged)
  }

  @Test func transportTimeoutAndFailureRemainDistinctClosedStatuses() async {
    let before = generation(running: false, pid: nil, runs: 3)
    let after = generation(running: false, pid: nil, runs: 3)
    let timeout = await makeProbe(
      transport: ProbeTransport(evidence: failureEvidence(.timeout), peerPID: nil),
      observer: ProbeGenerationObserver([before, after])
    ).probe(timeoutMilliseconds: 500)
    let failure = await makeProbe(
      transport: ProbeTransport(evidence: failureEvidence(.connectionInvalid), peerPID: nil),
      observer: ProbeGenerationObserver([before, after])
    ).probe(timeoutMilliseconds: 500)

    #expect(timeout.status == .timeout)
    #expect(timeout.probePerformed)
    #expect(timeout.connectionCancelRequested)
    #expect(failure.status == .unreachable)
    #expect(failure.probePerformed)
    #expect(failure.connectionCancelRequested)
  }

  @Test func preCancelledTaskDoesNotObserveOrRequestTransport() async {
    let gate = ProbeGate()
    let observer = ProbeGenerationObserver([generation(running: false, pid: nil, runs: 4)])
    let transport = ProbeTransport(evidence: acceptedEvidence(), peerPID: 400)
    let probe = makeProbe(transport: transport, observer: observer)
    let task = Task {
      await gate.wait()
      return await probe.probe(timeoutMilliseconds: 500)
    }
    task.cancel()
    await gate.release()

    let result = await task.value

    #expect(result.status == .cancelled)
    #expect(!result.probePerformed)
    #expect(result.finalGeneration == .unavailable)
    #expect(await observer.callCount == 0)
    #expect(await transport.callCount == 0)
  }

  @Test func cancellationAfterTransportStartsStillReturnsFinalGeneration() async {
    let before = generation(running: false, pid: nil, runs: 4)
    let after = generation(running: false, pid: nil, runs: 5)
    let observer = ProbeGenerationObserver([before, after])
    let transport = CancellableProbeTransport()
    let probe = VendorXPCReachabilityProbe(
      transport: transport,
      generationObserver: observer,
      preflightChecker: ProbePreflightChecker(safePreflight())
    )
    let task = Task { await probe.probe(timeoutMilliseconds: 500) }
    await transport.waitUntilStarted()

    task.cancel()
    let result = await task.value

    #expect(result.status == .cancelled)
    #expect(result.probePerformed)
    #expect(!result.transportAccepted)
    #expect(result.finalGeneration == after)
    #expect(result.connectionCancelRequested)
    #expect(await observer.callCount == 2)
  }

  private func makeProbe(
    transport: ProbeTransport,
    observer: ProbeGenerationObserver,
    preflight: VendorXPCPreflightEvidence? = nil
  ) -> VendorXPCReachabilityProbe {
    VendorXPCReachabilityProbe(
      transport: transport,
      generationObserver: observer,
      preflightChecker: ProbePreflightChecker(preflight ?? safePreflight())
    )
  }

  private func acceptedEvidence(
    peerValidated: Bool = false
  ) -> VendorXPCGetVersionEvidence {
    VendorXPCGetVersionEvidence(
      outcome: .accepted,
      versionByteLength: 5,
      versionMatchesLockedBuild: true,
      getVersionSuccess: true,
      replyPeerGenerationValidated: peerValidated,
      connectionCancelRequested: true
    )
  }

  private func failureEvidence(
    _ outcome: VendorXPCGetVersionOutcome
  ) -> VendorXPCGetVersionEvidence {
    VendorXPCGetVersionEvidence(
      outcome: outcome,
      connectionCancelRequested: true
    )
  }

  private func safePreflight() -> VendorXPCPreflightEvidence {
    VendorXPCPreflightEvidence(
      guiProcessAbsent: true,
      helperProcessAbsent: true,
      otherVendorHelperProcessesAbsent: true,
      helperLaunchdInactive: true,
      dnsRecoveryFileAbsent: true,
      vendorLogRotationSafe: true
    )
  }

  private func blockedPreflight() -> VendorXPCPreflightEvidence {
    VendorXPCPreflightEvidence(
      guiProcessAbsent: false,
      helperProcessAbsent: true,
      otherVendorHelperProcessesAbsent: true,
      helperLaunchdInactive: true,
      dnsRecoveryFileAbsent: true,
      vendorLogRotationSafe: true
    )
  }

  private func generation(
    running: Bool,
    pid: Int?,
    runs: Int
  ) -> VendorHelperGenerationSnapshot {
    VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: running,
      inactiveConfirmed: !running,
      activeCount: running ? 1 : 0,
      pid: pid,
      runs: runs
    )
  }
}
