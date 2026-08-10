import Foundation
import Security

enum TLSAsyncTrustEvaluationError: Error, Equatable, Sendable {
  case invalidChain
  case trustSetup
  case evaluationStart
  case timedOut
  case duplicateCallback
  case invalidState
}

protocol TLSAsyncTrustEvaluating: AnyObject, Sendable {
  func evaluate(
    chain: TLSPeerCertificateChain,
    exactHost: String,
    phase: @escaping @Sendable (TLSTrustEvaluationPhase) -> Void,
    completion:
      @escaping @Sendable (
        Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>
      ) -> Void
  )
  func cancel()
}

final class AsyncSecTrustEvaluator: TLSAsyncTrustEvaluating, @unchecked Sendable {
  typealias EvaluateAPI =
    @Sendable (
      SecTrust,
      DispatchQueue,
      @escaping (SecTrust, Bool, CFError?) -> Void
    ) -> OSStatus

  static let evaluationTimeout: DispatchTimeInterval = .seconds(5)

  private let lock = NSLock()
  private let evaluationQueue: DispatchQueue
  private let deadlineQueue: DispatchQueue
  private let timeout: DispatchTimeInterval
  private let evaluateAPI: EvaluateAPI
  private var session: TLSAsyncTrustSession?
  private var terminal = false

  init(
    evaluationQueue: DispatchQueue = DispatchQueue(
      label: "org.powervpn.tls-peer-evidence.trust"
    ),
    deadlineQueue: DispatchQueue = DispatchQueue(
      label: "org.powervpn.tls-peer-evidence.trust-deadline"
    ),
    timeout: DispatchTimeInterval = evaluationTimeout,
    evaluateAPI: @escaping EvaluateAPI = { trust, queue, callback in
      SecTrustEvaluateAsyncWithError(trust, queue, callback)
    }
  ) {
    self.evaluationQueue = evaluationQueue
    self.deadlineQueue = deadlineQueue
    self.timeout = timeout
    self.evaluateAPI = evaluateAPI
  }

  func evaluate(
    chain: TLSPeerCertificateChain,
    exactHost: String,
    phase: @escaping @Sendable (TLSTrustEvaluationPhase) -> Void,
    completion:
      @escaping @Sendable (
        Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>
      ) -> Void
  ) {
    let session = TLSAsyncTrustSession(
      chain: chain,
      exactHost: exactHost,
      evaluationQueue: evaluationQueue,
      deadlineQueue: deadlineQueue,
      timeout: timeout,
      evaluateAPI: evaluateAPI,
      phase: phase
    ) { [weak self] result in
      self?.finish(result, completion: completion)
    }
    let shouldStart = lock.withLock {
      guard !terminal, self.session == nil else { return false }
      self.session = session
      return true
    }
    guard shouldStart else {
      completion(.failure(.invalidState))
      return
    }
    session.start()
  }

  func cancel() {
    let retained = lock.withLock {
      terminal = true
      let retained = session
      session = nil
      return retained
    }
    retained?.cancel()
  }

  private func finish(
    _ result: Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>,
    completion:
      @escaping @Sendable (
        Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>
      ) -> Void
  ) {
    let shouldDeliver = lock.withLock {
      guard !terminal, session != nil else { return false }
      terminal = true
      session = nil
      return true
    }
    if shouldDeliver { completion(result) }
  }
}
