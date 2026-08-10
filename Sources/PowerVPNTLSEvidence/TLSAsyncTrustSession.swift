import Foundation
import Security

struct TLSAsyncTrustSessionHooks: Sendable {
  let afterTrustConstruction: @Sendable () -> Void
  let beforeBasicReservation: @Sendable () -> Void
  let afterReservation: @Sendable (TLSAsyncTrustPolicySlot) -> Void

  init(
    afterTrustConstruction: @escaping @Sendable () -> Void = {},
    beforeBasicReservation: @escaping @Sendable () -> Void = {},
    afterReservation: @escaping @Sendable (TLSAsyncTrustPolicySlot) -> Void = { _ in }
  ) {
    self.afterTrustConstruction = afterTrustConstruction
    self.beforeBasicReservation = beforeBasicReservation
    self.afterReservation = afterReservation
  }
}

final class TLSAsyncTrustSession: @unchecked Sendable {
  private let evaluationQueue: DispatchQueue
  private let deadlineQueue: DispatchQueue
  private let deadline: DispatchTime
  private let evaluateAPI: AsyncSecTrustEvaluator.EvaluateAPI
  private let exactHost: String
  private let hooks: TLSAsyncTrustSessionHooks
  private let state: TLSAsyncTrustState

  init(
    chain: TLSPeerCertificateChain,
    exactHost: String,
    evaluationQueue: DispatchQueue,
    deadlineQueue: DispatchQueue,
    timeout: DispatchTimeInterval,
    evaluateAPI: @escaping AsyncSecTrustEvaluator.EvaluateAPI,
    phase: @escaping @Sendable (TLSTrustEvaluationPhase) -> Void,
    hooks: TLSAsyncTrustSessionHooks = TLSAsyncTrustSessionHooks(),
    completion: @escaping TLSAsyncTrustCompletion
  ) {
    self.exactHost = exactHost
    self.evaluationQueue = evaluationQueue
    self.deadlineQueue = deadlineQueue
    deadline = .now() + timeout
    self.evaluateAPI = evaluateAPI
    self.hooks = hooks
    state = TLSAsyncTrustState(chain: chain, phase: phase, completion: completion)
  }

  func start() {
    deadlineQueue.asyncAfter(deadline: deadline) { [weak self] in self?.expire() }
    evaluationQueue.async { [weak self] in self?.startOnEvaluationQueue() }
  }

  func cancel() { state.cancel() }

  private func startOnEvaluationQueue() {
    dispatchPrecondition(condition: .onQueue(evaluationQueue))
    guard let chain = state.chainForSetup() else { return }
    guard let certificates = makeCertificates(chain) else {
      deliver(state.fail(.invalidChain))
      return
    }
    guard
      let ssl = makeTrust(
        certificates,
        primaryPolicy: SecPolicyCreateSSL(true, exactHost as CFString)
      ),
      let basic = makeTrust(certificates, primaryPolicy: SecPolicyCreateBasicX509())
    else {
      deliver(state.fail(.trustSetup))
      return
    }
    guard state.installTrusts(ssl: ssl, basic: basic) else { return }
    hooks.afterTrustConstruction()

    guard startEvaluation(ssl, slot: .ssl) else { return }
    hooks.beforeBasicReservation()
    guard state.isActive else { return }
    _ = startEvaluation(basic, slot: .basic)
  }

  private func startEvaluation(
    _ trust: SecTrust,
    slot: TLSAsyncTrustPolicySlot
  ) -> Bool {
    guard let token = state.reserve(slot) else { return false }
    hooks.afterReservation(slot)
    // Reservation commits invocation permission; a later terminal state only suppresses output.
    let status = evaluateAPI(trust, evaluationQueue) { [weak self] _, accepted, error in
      self?.record(accepted: accepted, error: error, token: token)
    }
    deliver(state.reconcile(token, status: status))
    return status == errSecSuccess && state.isActive
  }

  private func record(
    accepted: Bool,
    error: CFError?,
    token: TLSAsyncTrustPolicyToken
  ) {
    let assessment = TLSTrustAssessment(
      accepted: accepted,
      category: accepted ? .accepted : TLSTrustSnapshotBuilder.category(for: error)
    )
    deliver(state.complete(token, assessment: assessment))
  }

  private func expire() { deliver(state.expire()) }

  private func deliver(_ delivery: TLSAsyncTrustDelivery?) { delivery?.resolve() }

  private func makeCertificates(_ chain: TLSPeerCertificateChain) -> [SecCertificate]? {
    let certificates = chain.certificateDER.compactMap {
      SecCertificateCreateWithData(nil, $0 as CFData)
    }
    return certificates.count == chain.certificateDER.count ? certificates : nil
  }

  private func makeTrust(
    _ certificates: [SecCertificate],
    primaryPolicy: SecPolicy
  ) -> SecTrust? {
    let flags = kSecRevocationUseAnyAvailableMethod | kSecRevocationNetworkAccessDisabled
    guard let revocation = SecPolicyCreateRevocation(flags) else { return nil }
    var trust: SecTrust?
    guard
      SecTrustCreateWithCertificates(
        certificates as CFArray,
        [primaryPolicy, revocation] as CFArray,
        &trust
      ) == errSecSuccess, let trust,
      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess
    else { return nil }
    return trust
  }
}
