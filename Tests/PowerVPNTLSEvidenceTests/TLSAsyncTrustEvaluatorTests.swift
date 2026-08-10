import Foundation
import Security
import Testing

@testable import PowerVPNTLSEvidence

@Suite(.serialized) struct TLSAsyncTrustEvaluatorTests {
  @Test func inlineAndAsyncCallbacksCompleteBothPolicies() throws {
    let chain = try certificateChain()
    for asynchronous in [false, true] {
      let phases = TrustPhaseRecorder()
      let result = LocalTLSLatch<
        Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>
      >()
      let evaluator = AsyncSecTrustEvaluator { trust, queue, callback in
        dispatchPrecondition(condition: .onQueue(queue))
        if asynchronous {
          let invocation = DeferredTrustCallback(trust: trust, callback: callback)
          queue.async { invocation.call(accepted: true) }
        } else {
          callback(trust, false, nil)
        }
        return errSecSuccess
      }
      evaluator.evaluate(
        chain: chain,
        exactHost: "127.0.0.1",
        phase: phases.record,
        completion: result.resolve
      )

      let snapshot = try #require(result.wait(timeout: .seconds(2))).get()
      #expect(snapshot.sslTrust.accepted == asynchronous)
      #expect(snapshot.basicTrust.accepted == asynchronous)
      let expected: [TLSTrustEvaluationPhase] =
        asynchronous
        ? [.sslStarted, .basicStarted, .sslCompleted, .basicCompleted]
        : [.sslStarted, .sslCompleted, .basicStarted, .basicCompleted]
      #expect(phases.values == expected)
    }
  }

  @Test func immediateStatusFailureFailsWithoutWaitingForCallback() throws {
    let phases = TrustPhaseRecorder()
    let result = LocalTLSLatch<Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>>()
    let evaluator = AsyncSecTrustEvaluator { _, queue, _ in
      dispatchPrecondition(condition: .onQueue(queue))
      return errSecParam
    }
    evaluator.evaluate(
      chain: try certificateChain(),
      exactHost: "127.0.0.1",
      phase: phases.record,
      completion: result.resolve
    )

    #expect(try #require(result.wait(timeout: .seconds(2))).failure == .evaluationStart)
    #expect(phases.values == [.sslStarted])
  }

  @Test func oneAbsoluteDeadlineIgnoresLateCallbacks() throws {
    let callbacks = TrustCallbackStore()
    let phases = TrustPhaseRecorder()
    let completions = TrustResultRecorder()
    let result = LocalTLSLatch<Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>>()
    let evaluator = AsyncSecTrustEvaluator(
      timeout: .milliseconds(20)
    ) { trust, queue, callback in
      dispatchPrecondition(condition: .onQueue(queue))
      callbacks.append(trust: trust, callback: callback)
      return errSecSuccess
    }
    evaluator.evaluate(
      chain: try certificateChain(),
      exactHost: "127.0.0.1",
      phase: phases.record
    ) { value in
      completions.record(value)
      result.resolve(value)
    }

    #expect(try #require(result.wait(timeout: .seconds(2))).failure == .timedOut)
    callbacks.invokeAll()
    _ = DispatchSemaphore(value: 0).wait(timeout: .now() + .milliseconds(30))
    #expect(completions.count == 1)
    #expect(phases.values.last == .deadlineExpired)
    #expect(!phases.values.contains(.sslCompleted))
    #expect(!phases.values.contains(.basicCompleted))
  }

  @Test func duplicatePolicyCallbackFailsClosed() throws {
    let result = LocalTLSLatch<Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>>()
    let evaluator = AsyncSecTrustEvaluator { trust, _, callback in
      callback(trust, false, nil)
      callback(trust, false, nil)
      return errSecSuccess
    }
    evaluator.evaluate(
      chain: try certificateChain(),
      exactHost: "127.0.0.1",
      phase: { _ in },
      completion: result.resolve
    )
    #expect(try #require(result.wait(timeout: .seconds(2))).failure == .duplicateCallback)
  }

  @Test func sessionRetainsTrustsUntilDelayedCallbacksFinish() throws {
    let callbacks = WeakTrustCallbackStore()
    let result = LocalTLSLatch<Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>>()
    let evaluator = AsyncSecTrustEvaluator { trust, _, callback in
      callbacks.append(trust: trust, callback: callback)
      return errSecSuccess
    }
    evaluator.evaluate(
      chain: try certificateChain(),
      exactHost: "127.0.0.1",
      phase: { _ in },
      completion: result.resolve
    )

    #expect(callbacks.waitUntilReady())
    #expect(callbacks.allTrustsAlive)
    #expect(callbacks.invokeAll())
    _ = try #require(result.wait(timeout: .seconds(2))).get()
  }

  @Test func systemAsyncEvaluationIsBoundedAndValueFree() throws {
    let result = LocalTLSLatch<Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>>()
    let evaluator = AsyncSecTrustEvaluator(timeout: .seconds(2))
    evaluator.evaluate(
      chain: try certificateChain(),
      exactHost: "localhost",
      phase: { _ in },
      completion: result.resolve
    )
    let snapshot = try #require(result.wait(timeout: .seconds(3))).get()
    #expect(snapshot.orderedCertificateSHA256.count == 1)
    #expect(snapshot.orderedCertificateSHA256[0].utf8.count == 64)
    #expect(snapshot.leafSPKISHA256.utf8.count == 64)
    #expect(!snapshot.sslTrust.accepted)
    #expect(!snapshot.basicTrust.accepted)
  }

  private func certificateChain() throws -> TLSPeerCertificateChain {
    TLSPeerCertificateChain(certificateDER: [try fixtureDER("rsa-cert")])
  }
}

extension Result where Failure == TLSAsyncTrustEvaluationError {
  fileprivate var failure: TLSAsyncTrustEvaluationError? {
    if case .failure(let error) = self { return error }
    return nil
  }
}

private final class TrustPhaseRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var phases: [TLSTrustEvaluationPhase] = []
  var values: [TLSTrustEvaluationPhase] { lock.withLock { phases } }
  func record(_ phase: TLSTrustEvaluationPhase) { lock.withLock { phases.append(phase) } }
}

private final class TrustCallbackStore: @unchecked Sendable {
  typealias Callback = (SecTrust, Bool, CFError?) -> Void
  private let lock = NSLock()
  private var callbacks: [(SecTrust, Callback)] = []

  func append(trust: SecTrust, callback: @escaping Callback) {
    lock.withLock { callbacks.append((trust, callback)) }
  }

  func invokeAll() {
    let retained = lock.withLock {
      let retained = callbacks
      callbacks.removeAll()
      return retained
    }
    for (trust, callback) in retained { callback(trust, false, nil) }
  }
}

private final class TrustResultRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var results = 0
  var count: Int { lock.withLock { results } }
  func record(_: Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>) {
    lock.withLock { results += 1 }
  }
}

private final class DeferredTrustCallback: @unchecked Sendable {
  typealias Callback = (SecTrust, Bool, CFError?) -> Void
  private let trust: SecTrust
  private let callback: Callback

  init(trust: SecTrust, callback: @escaping Callback) {
    self.trust = trust
    self.callback = callback
  }

  func call(accepted: Bool) { callback(trust, accepted, nil) }
}

private final class WeakTrustCallbackStore: @unchecked Sendable {
  typealias Callback = (SecTrust, Bool, CFError?) -> Void
  private let lock = NSLock()
  private let ready = DispatchSemaphore(value: 0)
  private var trusts: [WeakTrustReference] = []
  private var callbacks: [Callback] = []

  func append(trust: SecTrust, callback: @escaping Callback) {
    let isReady = lock.withLock {
      trusts.append(WeakTrustReference(trust))
      callbacks.append(callback)
      return callbacks.count == 2
    }
    if isReady { ready.signal() }
  }

  func waitUntilReady() -> Bool {
    ready.wait(timeout: .now() + .seconds(2)) == .success
  }

  var allTrustsAlive: Bool {
    lock.withLock { trusts.count == 2 && trusts.allSatisfy { $0.value != nil } }
  }

  func invokeAll() -> Bool {
    let retained = lock.withLock { () -> [(SecTrust, Callback)]? in
      let values = trusts.compactMap(\.value)
      guard values.count == callbacks.count else { return nil }
      return Array(zip(values, callbacks))
    }
    guard let retained else { return false }
    for (trust, callback) in retained { callback(trust, false, nil) }
    return true
  }
}

private final class WeakTrustReference {
  weak var value: SecTrust?
  init(_ value: SecTrust) { self.value = value }
}
