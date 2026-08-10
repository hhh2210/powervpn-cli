import Foundation
import Security

typealias TLSAsyncTrustCompletion =
  @Sendable (
    Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>
  ) -> Void

enum TLSAsyncTrustPolicySlot: Sendable {
  case ssl
  case basic

  var startedPhase: TLSTrustEvaluationPhase {
    self == .ssl ? .sslStarted : .basicStarted
  }

  var completedPhase: TLSTrustEvaluationPhase {
    self == .ssl ? .sslCompleted : .basicCompleted
  }
}

struct TLSAsyncTrustPolicyToken: Equatable, Sendable {
  let slot: TLSAsyncTrustPolicySlot
  let generation: UInt64
}

struct TLSAsyncTrustDelivery: Sendable {
  enum Payload: Sendable {
    case snapshot(
      TLSPeerCertificateChain,
      ssl: TLSTrustAssessment,
      basic: TLSTrustAssessment
    )
    case failure(TLSAsyncTrustEvaluationError)
  }

  let payload: Payload
  let completion: TLSAsyncTrustCompletion

  func resolve() {
    switch payload {
    case .snapshot(let chain, let ssl, let basic):
      completion(
        TLSTrustSnapshotBuilder.make(
          chain: chain,
          sslTrust: ssl,
          basicTrust: basic
        ).mapError { _ in .invalidChain }
      )
    case .failure(let error):
      completion(.failure(error))
    }
  }
}

final class TLSAsyncTrustState: @unchecked Sendable {
  enum PolicyLifecycle: Sendable {
    case notStarted
    case reserved
    case running
    case completed
  }

  private struct PolicyRecord {
    var lifecycle: PolicyLifecycle = .notStarted
    var generation: UInt64?
    var invocationSucceeded = false
    var assessment: TLSTrustAssessment?
  }

  // Phase publication is part of the transition's linearization point. The bounded
  // internal sink may synchronously reenter cancellation, so this lock is recursive.
  private let lock = NSRecursiveLock()
  private let phase: @Sendable (TLSTrustEvaluationPhase) -> Void
  private var completion: TLSAsyncTrustCompletion?
  private var chain: TLSPeerCertificateChain?
  private var sslTrust: SecTrust?
  private var basicTrust: SecTrust?
  private var ssl = PolicyRecord()
  private var basic = PolicyRecord()
  private var nextGeneration: UInt64 = 1
  private var terminal = false

  init(
    chain: TLSPeerCertificateChain,
    phase: @escaping @Sendable (TLSTrustEvaluationPhase) -> Void,
    completion: @escaping TLSAsyncTrustCompletion
  ) {
    self.chain = chain
    self.phase = phase
    self.completion = completion
  }

  func chainForSetup() -> TLSPeerCertificateChain? {
    lock.withLock { terminal ? nil : chain }
  }

  func installTrusts(ssl: SecTrust, basic: SecTrust) -> Bool {
    lock.withLock {
      guard !terminal else { return false }
      sslTrust = ssl
      basicTrust = basic
      return true
    }
  }

  func reserve(_ slot: TLSAsyncTrustPolicySlot) -> TLSAsyncTrustPolicyToken? {
    lock.withLock {
      guard !terminal else { return nil }
      var record = record(for: slot)
      guard record.lifecycle == .notStarted else { return nil }
      let token = TLSAsyncTrustPolicyToken(slot: slot, generation: nextGeneration)
      nextGeneration += 1
      record.lifecycle = .reserved
      record.generation = token.generation
      setRecord(record, for: slot)
      // Committing the record and Started phase is the policy's logical start.
      phase(slot.startedPhase)
      return token
    }
  }

  func reconcile(
    _ token: TLSAsyncTrustPolicyToken,
    status: OSStatus
  ) -> TLSAsyncTrustDelivery? {
    lock.withLock {
      guard !terminal else { return nil }
      var record = record(for: token.slot)
      guard record.generation == token.generation,
        record.lifecycle == .reserved || record.lifecycle == .running
          || record.lifecycle == .completed
      else { return terminalDelivery(.failure(.invalidState)) }
      guard status == errSecSuccess else {
        return terminalDelivery(.failure(.evaluationStart))
      }
      record.invocationSucceeded = true
      if record.lifecycle == .reserved { record.lifecycle = .running }
      setRecord(record, for: token.slot)
      return successIfReady()
    }
  }

  func complete(
    _ token: TLSAsyncTrustPolicyToken,
    assessment: TLSTrustAssessment
  ) -> TLSAsyncTrustDelivery? {
    lock.withLock {
      guard !terminal else { return nil }
      var record = record(for: token.slot)
      guard record.generation == token.generation else {
        return terminalDelivery(.failure(.invalidState))
      }
      guard record.lifecycle != .completed else {
        return terminalDelivery(.failure(.duplicateCallback))
      }
      guard record.lifecycle == .reserved || record.lifecycle == .running else {
        return terminalDelivery(.failure(.invalidState))
      }
      record.lifecycle = .completed
      record.assessment = assessment
      setRecord(record, for: token.slot)
      phase(token.slot.completedPhase)
      return successIfReady()
    }
  }

  func fail(_ error: TLSAsyncTrustEvaluationError) -> TLSAsyncTrustDelivery? {
    lock.withLock {
      guard !terminal else { return nil }
      return terminalDelivery(.failure(error))
    }
  }

  func expire() -> TLSAsyncTrustDelivery? {
    lock.withLock {
      guard !terminal else { return nil }
      phase(.deadlineExpired)
      return terminalDelivery(.failure(.timedOut))
    }
  }

  func cancel() {
    lock.withLock {
      guard !terminal else { return }
      terminal = true
      completion = nil
      releaseSensitiveState()
    }
  }

  var isActive: Bool { lock.withLock { !terminal } }

  private func successIfReady() -> TLSAsyncTrustDelivery? {
    guard ssl.lifecycle == .completed, ssl.invocationSucceeded,
      basic.lifecycle == .completed, basic.invocationSucceeded,
      let sslAssessment = ssl.assessment, let basicAssessment = basic.assessment,
      let chain
    else { return nil }
    return terminalDelivery(
      .snapshot(chain, ssl: sslAssessment, basic: basicAssessment)
    )
  }

  private func terminalDelivery(
    _ payload: TLSAsyncTrustDelivery.Payload
  ) -> TLSAsyncTrustDelivery? {
    guard !terminal, let completion else { return nil }
    terminal = true
    self.completion = nil
    releaseSensitiveState()
    return TLSAsyncTrustDelivery(payload: payload, completion: completion)
  }

  private func releaseSensitiveState() {
    chain = nil
    sslTrust = nil
    basicTrust = nil
  }

  private func record(for slot: TLSAsyncTrustPolicySlot) -> PolicyRecord {
    slot == .ssl ? ssl : basic
  }

  private func setRecord(_ record: PolicyRecord, for slot: TLSAsyncTrustPolicySlot) {
    if slot == .ssl { ssl = record } else { basic = record }
  }
}
