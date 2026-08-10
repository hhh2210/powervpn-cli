import Foundation
import Testing

@testable import PowerVPNTLSEvidence

@Suite struct TLSPeerObserverTests {
  @Test func capturedEvidenceWinsOnceAndCancelsSource() async {
    let source = FakeTLSTrustSource()
    let observer = TLSPeerObserver(source: source, timeoutNanoseconds: 1_000_000_000)
    let task = Task { await observer.observe() }
    await source.waitUntilStarted()
    source.recordVerifyCallback()
    source.recordCompleteEvidence()
    source.emit(.captured(Self.snapshot))
    source.emit(.invalidEvidence)

    let report = await task.value
    #expect(report.status == .observed)
    #expect(report.chainLength == 1)
    #expect(report.leafSPKISHA256 == String(repeating: "b", count: 64))
    #expect(report.transportProgress.verifyCallbackObserved)
    #expect(!report.transportProgress.failedObserved)
    #expect(report.evidenceProgress.transportEvidenceComplete)
    #expect(report.evidenceProgress.trustEvidenceComplete)
    #expect(source.startCount == 1)
    #expect(source.cancelCount == 1)
    #expect(source.snapshotCount == 1)
  }

  @Test func unavailableAndInvalidEvidenceRemainDistinct() async {
    for (event, expected) in [
      (TLSTrustSourceEvent.unavailable, TLSPeerEvidenceStatus.unavailable),
      (.invalidEvidence, .invalidEvidence),
    ] {
      let source = FakeTLSTrustSource(synchronousEvent: event)
      let report = await TLSPeerObserver(
        source: source,
        timeoutNanoseconds: 1_000_000_000
      ).observe()
      #expect(report.status == expected)
      #expect(report.chainLength == 0)
      #expect(source.cancelCount == 1)
    }
  }

  @Test func timeoutIsBoundedAndCancelsSource() async {
    let source = FakeTLSTrustSource()
    let report = await TLSPeerObserver(
      source: source,
      timeoutNanoseconds: 5_000_000
    ).observe()
    #expect(report.status == .timedOut)
    #expect(report.transportProgress.connectionStarted)
    #expect(!report.transportProgress.verifyCallbackObserved)
    #expect(source.startCount == 1)
    #expect(source.cancelCount == 1)
  }

  @Test func timeoutPreservesWaitingAndVerifyEntryProgress() async {
    for mark in [
      { (source: FakeTLSTrustSource) in source.recordWaiting() },
      { (source: FakeTLSTrustSource) in source.recordVerifyCallback() },
    ] {
      let source = FakeTLSTrustSource()
      let task = Task {
        await TLSPeerObserver(
          source: source,
          timeoutNanoseconds: 20_000_000
        ).observe()
      }
      await source.waitUntilStarted()
      source.recordPreparing()
      mark(source)
      let report = await task.value
      #expect(report.status == .timedOut)
      #expect(report.transportProgress.connectionStarted)
      #expect(report.transportProgress.preparingObserved)
      #expect(
        report.transportProgress.waitingObserved
          || report.transportProgress.verifyCallbackObserved)
    }
  }

  @Test func parentCancellationWinsWithoutWaitingForSource() async {
    let source = FakeTLSTrustSource()
    let task = Task {
      await TLSPeerObserver(
        source: source,
        timeoutNanoseconds: 1_000_000_000
      ).observe()
    }
    await source.waitUntilStarted()
    source.recordPreparing()
    task.cancel()

    let report = await task.value
    #expect(report.status == .cancelled)
    #expect(report.transportProgress.preparingObserved)
    #expect(source.cancelCount == 1)
  }

  @Test func readyFailsClosedWithoutBecomingObserved() async {
    let source = FakeTLSTrustSource()
    let task = Task {
      await TLSPeerObserver(
        source: source,
        timeoutNanoseconds: 1_000_000_000
      ).observe()
    }
    await source.waitUntilStarted()
    source.recordReady()
    source.emit(.invalidEvidence)
    let report = await task.value
    #expect(report.status == .invalidEvidence)
    #expect(report.transportProgress.readyObserved)
    #expect(!report.verifyAccepted)
  }

  @Test func verifyCompletionRejectsExactlyOnce() {
    let results = LockedBoolRecorder()
    let progress = TLSPeerProgressRecorder()
    let completion = TLSVerifyCompletionOnce(
      { results.record($0) },
      onInvoke: { progress.recordVerifyInvoked() },
      onReturn: { progress.recordVerifyReturned() }
    )
    completion.reject()
    completion.reject()
    #expect(results.values == [false])
    #expect(progress.snapshot().evidence.verifyCompletionInvokedWithFalse)
    #expect(progress.snapshot().evidence.verifyCompletionReturned)
    #expect(!progress.snapshot().evidence.transportEvidenceComplete)
    #expect(progress.snapshot().isValid)
  }

  @Test func transportCompletionRequiresReturnedMetadataAndNoDuplicateVerify() {
    let progress = TLSPeerProgressRecorder()
    progress.recordConnectionStarted()
    progress.recordVerifyEntry(isDuplicate: false)
    progress.recordMetadataAccessible()
    progress.recordDERCopyCompleted()
    progress.recordVerifyInvoked()
    #expect(!progress.snapshot().evidence.transportEvidenceComplete)

    progress.recordVerifyReturned()
    #expect(progress.snapshot().evidence.transportEvidenceComplete)

    progress.recordVerifyEntry(isDuplicate: true)
    #expect(!progress.snapshot().evidence.transportEvidenceComplete)
    #expect(progress.snapshot().isValid)
  }

  @Test func duplicateVerifyInvocationFailsClosed() {
    let gate = TLSVerifyInvocationGate()
    #expect(gate.begin())
    #expect(!gate.begin())
    #expect(!gate.begin())
    #expect(gate.hasBegun)
  }

  @Test func productionSocketObservationHoldIsShortAndBounded() {
    #expect(NetworkTLSTrustSource.observationHoldMilliseconds >= 200)
    #expect(NetworkTLSTrustSource.observationHoldMilliseconds <= 500)
    #expect(TLSPeerEvidenceRuntime.sealedTimeoutNanoseconds == 15_000_000_000)
  }

  private static let snapshot = TLSTrustSnapshot(
    orderedCertificateSHA256: [String(repeating: "a", count: 64)],
    leafSPKISHA256: String(repeating: "b", count: 64),
    sslTrust: TLSTrustAssessment(accepted: false, category: .untrustedChain),
    basicTrust: TLSTrustAssessment(accepted: false, category: .untrustedChain)
  )
}

private final class FakeTLSTrustSource: TLSTrustSource, @unchecked Sendable {
  private let lock = NSLock()
  private let synchronousEvent: TLSTrustSourceEvent?
  private var handler: (@Sendable (TLSTrustSourceEvent) -> Void)?
  private var starts = 0
  private var cancels = 0
  private var snapshots = 0
  private let progress = TLSPeerProgressRecorder()

  init(synchronousEvent: TLSTrustSourceEvent? = nil) {
    self.synchronousEvent = synchronousEvent
  }

  var startCount: Int { lock.withLock { starts } }
  var cancelCount: Int { lock.withLock { cancels } }
  var snapshotCount: Int { lock.withLock { snapshots } }

  func start(_ handler: @escaping @Sendable (TLSTrustSourceEvent) -> Void) {
    lock.withLock {
      starts += 1
      self.handler = handler
    }
    progress.recordConnectionStarted()
    if let synchronousEvent { handler(synchronousEvent) }
  }

  func cancel() {
    lock.withLock {
      cancels += 1
      handler = nil
    }
  }

  func emit(_ event: TLSTrustSourceEvent) {
    let callback = lock.withLock { handler }
    callback?(event)
  }

  func progressSnapshot() -> TLSPeerProgressSnapshot {
    lock.withLock { snapshots += 1 }
    return progress.snapshot()
  }

  func recordPreparing() { progress.recordPreparing() }
  func recordWaiting() { progress.recordWaiting() }
  func recordVerifyCallback() { progress.recordVerifyEntry(isDuplicate: false) }
  func recordFailed() { progress.recordFailed() }
  func recordReady() { progress.recordReady() }
  func recordCompleteEvidence() {
    progress.recordMetadataAccessible()
    progress.recordDERCopyCompleted()
    progress.recordVerifyInvoked()
    progress.recordVerifyReturned()
    progress.record(.sslStarted)
    progress.record(.sslCompleted)
    progress.record(.basicStarted)
    progress.record(.basicCompleted)
  }

  func waitUntilStarted() async {
    for _ in 0..<1_000 {
      if startCount == 1 { return }
      await Task.yield()
    }
    Issue.record("fake TLS source did not start")
  }
}

private final class LockedBoolRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recorded: [Bool] = []
  var values: [Bool] { lock.withLock { recorded } }
  func record(_ value: Bool) { lock.withLock { recorded.append(value) } }
}
