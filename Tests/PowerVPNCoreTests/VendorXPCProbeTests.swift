import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorXPCProbeTests {
  @Test func acceptsExactReplyBoundToColdLaunchedGeneration() async {
    let transport = FakeVendorXPCTransport(evidence: acceptedEvidence())
    let observer = SequenceGenerationObserver([
      generation(running: false, pid: nil, runs: 11),
      generation(running: true, pid: 400, runs: 12),
      generation(running: true, pid: 400, runs: 12),
    ])
    let report = await VendorXPCProbe(
      transport: transport,
      generationObserver: observer,
      preflightChecker: FixedPreflightChecker(safePreflight())
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.status == .accepted)
    #expect(report.transportOutcome == .accepted)
    #expect(report.exactReplySchema)
    #expect(report.versionByteLength == 5)
    #expect(report.versionMatchesLockedBuild)
    #expect(report.getVersionSuccess)
    #expect(report.helperGenerationRelation == .launched)
    #expect(report.replyPeerMatchesObservedGeneration)
    #expect(report.connectionCancelRequested)
    #expect(report.transactionAccepted)
    #expect(await transport.callCount == 1)
  }

  @Test func preflightBlockNeverTouchesTransport() async {
    let transport = FakeVendorXPCTransport(evidence: acceptedEvidence())
    let blocked = VendorXPCPreflightEvidence(
      guiProcessAbsent: false,
      helperProcessAbsent: true,
      otherVendorHelperProcessesAbsent: true,
      helperLaunchdInactive: true,
      dnsRecoveryFileAbsent: true,
      vendorLogRotationSafe: true
    )
    let report = await VendorXPCProbe(
      transport: transport,
      generationObserver: SequenceGenerationObserver([
        generation(running: false, pid: nil, runs: 11)
      ]),
      preflightChecker: FixedPreflightChecker(blocked)
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.status == .preflightBlocked)
    #expect(report.transportOutcome == nil)
    #expect(!report.connectionCancelRequested)
    #expect(!report.transactionAccepted)
    #expect(await transport.callCount == 0)
  }

  @Test func acceptsReplyBoundBeforeColdHelperExits() async {
    let report = await VendorXPCProbe(
      transport: FakeVendorXPCTransport(evidence: acceptedEvidence()),
      generationObserver: SequenceGenerationObserver([
        generation(running: false, pid: nil, runs: 11),
        generation(running: true, pid: 400, runs: 12),
        generation(running: false, pid: nil, runs: 12),
      ]),
      preflightChecker: FixedPreflightChecker(safePreflight())
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.helperGenerationRelation == .launchedAndExited)
    #expect(report.replyPeerMatchesObservedGeneration)
    #expect(report.transactionAccepted)
  }

  @Test func exitedHelperCannotPassWithoutReplyTimeGenerationBinding() async {
    let report = await VendorXPCProbe(
      transport: FakeVendorXPCTransport(evidence: acceptedEvidence()),
      generationObserver: SequenceGenerationObserver([
        generation(running: false, pid: nil, runs: 11),
        generation(running: true, pid: 401, runs: 12),
        generation(running: false, pid: nil, runs: 12),
      ]),
      preflightChecker: FixedPreflightChecker(safePreflight())
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.transportOutcome == .accepted)
    #expect(report.helperGenerationRelation == .launchedAndExited)
    #expect(!report.replyPeerMatchesObservedGeneration)
    #expect(!report.transactionAccepted)
  }

  @Test func replyTimeRunDeltaMustBeExactlyOne() async {
    let report = await VendorXPCProbe(
      transport: FakeVendorXPCTransport(evidence: acceptedEvidence()),
      generationObserver: SequenceGenerationObserver([
        generation(running: false, pid: nil, runs: 11),
        generation(running: true, pid: 400, runs: 13),
        generation(running: true, pid: 400, runs: 13),
      ]),
      preflightChecker: FixedPreflightChecker(safePreflight())
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.helperGenerationRelation == .changed)
    #expect(!report.replyPeerMatchesObservedGeneration)
    #expect(!report.transactionAccepted)
  }

  @Test func stableButNonColdGenerationCannotPassR1() async {
    let report = await VendorXPCProbe(
      transport: FakeVendorXPCTransport(evidence: acceptedEvidence()),
      generationObserver: SequenceGenerationObserver([
        generation(running: true, pid: 400, runs: 12),
        generation(running: true, pid: 400, runs: 12),
        generation(running: true, pid: 400, runs: 12),
      ]),
      preflightChecker: FixedPreflightChecker(safePreflight())
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.helperGenerationRelation == .stable)
    #expect(!report.replyPeerMatchesObservedGeneration)
    #expect(!report.transactionAccepted)
  }

  @Test func timeoutRemainsDistinctAndValueFree() async throws {
    let evidence = VendorXPCGetVersionEvidence(
      outcome: .timeout,
      versionByteLength: nil,
      versionMatchesLockedBuild: false,
      getVersionSuccess: false,
      emptyDispatcherTailObserved: false,
      emptyReplyAcknowledgementObserved: false,
      replyPeerGenerationValidated: false,
      connectionCancelRequested: true
    )
    let report = await VendorXPCProbe(
      transport: FakeVendorXPCTransport(evidence: evidence, peerPID: nil),
      generationObserver: SequenceGenerationObserver([
        generation(running: false, pid: nil, runs: 11),
        generation(running: false, pid: nil, runs: 12),
      ]),
      preflightChecker: FixedPreflightChecker(safePreflight())
    ).getVersion(timeoutMilliseconds: 2_000)

    #expect(report.transportOutcome == .timeout)
    #expect(report.status == .transportFailed)
    #expect(report.connectionCancelRequested)
    #expect(!report.transactionAccepted)

    let encoded = try JSONEncoder().encode(report)
    let text = String(decoding: encoded, as: UTF8.self)
    #expect(!text.contains("24572"))
    #expect(!text.contains("pid"))
    #expect(!text.contains("rpc"))

    let object = try #require(
      JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    #expect(
      Set(object.keys) == [
        "connectionCancelRequested", "emptyDispatcherTailObserved",
        "emptyReplyAcknowledgementObserved", "evidenceClass", "exactReplySchema",
        "getVersionSuccess", "helperGenerationRelation", "mode", "preflight",
        "replyPeerMatchesObservedGeneration", "safety", "schemaVersion", "status",
        "transactionAccepted", "transportOutcome", "versionMatchesLockedBuild",
      ])
  }

  private func acceptedEvidence() -> VendorXPCGetVersionEvidence {
    VendorXPCGetVersionEvidence(
      outcome: .accepted,
      versionByteLength: 5,
      versionMatchesLockedBuild: true,
      getVersionSuccess: true,
      emptyDispatcherTailObserved: false,
      emptyReplyAcknowledgementObserved: false,
      replyPeerGenerationValidated: false,
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

private actor FakeVendorXPCTransport: VendorXPCTransporting {
  private let evidence: VendorXPCGetVersionEvidence
  private let peerPID: Int32?
  private(set) var callCount = 0

  init(evidence: VendorXPCGetVersionEvidence, peerPID: Int32? = 400) {
    self.evidence = evidence
    self.peerPID = peerPID
  }

  func getVersion(
    timeoutMilliseconds _: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) async -> VendorXPCGetVersionEvidence {
    callCount += 1
    let peerValidated = peerPID.map(peerGenerationValidator) ?? false
    return VendorXPCGetVersionEvidence(
      outcome: evidence.outcome,
      versionByteLength: evidence.versionByteLength,
      versionMatchesLockedBuild: evidence.versionMatchesLockedBuild,
      getVersionSuccess: evidence.getVersionSuccess,
      emptyDispatcherTailObserved: evidence.emptyDispatcherTailObserved,
      emptyReplyAcknowledgementObserved: evidence.emptyReplyAcknowledgementObserved,
      replyPeerGenerationValidated: peerValidated,
      connectionCancelRequested: evidence.connectionCancelRequested
    )
  }
}

private final class SequenceGenerationObserver: VendorHelperGenerationObserving,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var snapshots: [VendorHelperGenerationSnapshot]

  init(_ snapshots: [VendorHelperGenerationSnapshot]) {
    self.snapshots = snapshots
  }

  func observe() -> VendorHelperGenerationSnapshot {
    lock.lock()
    defer { lock.unlock() }
    if snapshots.count > 1 {
      return snapshots.removeFirst()
    }
    return snapshots[0]
  }
}

private struct FixedPreflightChecker: VendorXPCPreflightChecking {
  let evidence: VendorXPCPreflightEvidence

  init(_ evidence: VendorXPCPreflightEvidence) {
    self.evidence = evidence
  }

  func check(
    generation _: VendorHelperGenerationSnapshot
  ) -> VendorXPCPreflightEvidence {
    evidence
  }
}
