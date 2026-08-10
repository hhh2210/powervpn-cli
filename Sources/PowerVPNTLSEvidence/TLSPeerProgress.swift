import Foundation

struct TLSPeerProgressSnapshot: Equatable, Sendable {
  let transport: TLSConnectionProgress
  let evidence: TLSEvidenceProgress

  init(
    transport: TLSConnectionProgress = TLSConnectionProgress(),
    evidence: TLSEvidenceProgress = TLSEvidenceProgress()
  ) {
    self.transport = transport
    self.evidence = evidence
  }

  var isValid: Bool {
    let requiresActiveVerifyCallback =
      evidence.metadataChainAccessAttempted
      || evidence.duplicateVerifyCallbackObserved
    return transport.isValid && evidence.isValid
      && (!requiresActiveVerifyCallback || transport.verifyCallbackObserved)
  }
}

final class TLSPeerProgressRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var connectionStarted = false
  private var preparingObserved = false
  private var waitingObserved = false
  private var verifyCallbackObserved = false
  private var failedObserved = false
  private var readyObserved = false
  private var metadataAttempted = false
  private var metadataAccessible = false
  private var derCopied = false
  private var verifyInvoked = false
  private var verifyReturned = false
  private var sslStarted = false
  private var sslCompleted = false
  private var basicStarted = false
  private var basicCompleted = false
  private var deadlineExpired = false
  private var duplicateVerify = false

  func recordConnectionStarted() { lock.withLock { connectionStarted = true } }
  func recordPreparing() { lock.withLock { preparingObserved = true } }
  func recordWaiting() { lock.withLock { waitingObserved = true } }
  func recordFailed() { lock.withLock { failedObserved = true } }
  func recordReady() { lock.withLock { readyObserved = true } }

  func recordVerifyEntry(isDuplicate: Bool) {
    lock.withLock {
      verifyCallbackObserved = true
      if isDuplicate {
        duplicateVerify = true
      } else {
        metadataAttempted = true
      }
    }
  }

  func recordMetadataAccessible() { lock.withLock { metadataAccessible = true } }
  func recordDERCopyCompleted() { lock.withLock { derCopied = true } }
  func recordVerifyInvoked() { lock.withLock { verifyInvoked = true } }
  func recordVerifyReturned() { lock.withLock { verifyReturned = true } }

  func record(_ phase: TLSTrustEvaluationPhase) {
    lock.withLock {
      switch phase {
      case .sslStarted: sslStarted = true
      case .sslCompleted: sslCompleted = true
      case .basicStarted: basicStarted = true
      case .basicCompleted: basicCompleted = true
      case .deadlineExpired: deadlineExpired = true
      }
    }
  }

  func snapshot() -> TLSPeerProgressSnapshot {
    lock.withLock {
      TLSPeerProgressSnapshot(
        transport: TLSConnectionProgress(
          connectionStarted: connectionStarted,
          preparingObserved: preparingObserved,
          waitingObserved: waitingObserved,
          verifyCallbackObserved: verifyCallbackObserved,
          failedObserved: failedObserved,
          readyObserved: readyObserved
        ),
        evidence: TLSEvidenceProgress(
          metadataChainAccessAttempted: metadataAttempted,
          metadataChainAccessible: metadataAccessible,
          peerDERCopyCompleted: derCopied,
          verifyCompletionInvokedWithFalse: verifyInvoked,
          verifyCompletionReturned: verifyReturned,
          sslEvaluationStarted: sslStarted,
          sslEvaluationCompleted: sslCompleted,
          basicEvaluationStarted: basicStarted,
          basicEvaluationCompleted: basicCompleted,
          evaluationDeadlineExpired: deadlineExpired,
          duplicateVerifyCallbackObserved: duplicateVerify
        )
      )
    }
  }
}
