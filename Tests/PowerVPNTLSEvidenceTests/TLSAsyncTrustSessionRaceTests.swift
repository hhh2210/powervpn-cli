import Foundation
import Security
import Testing

@testable import PowerVPNTLSEvidence

@Suite(.serialized) struct TLSAsyncTrustSessionRaceTests {
  @Test func cancelAfterTrustConstructionPreventsSSLInvocation() throws {
    let barrier = SessionTestBarrier()
    let invocations = SessionTrustInvocationStore()
    let phases = SessionPhaseRecorder()
    let results = SessionResultRecorder()
    let queue = DispatchQueue(label: "tls-session-race.constructed")
    let session = try makeSession(
      queue: queue,
      invocations: invocations,
      phases: phases,
      results: results,
      hooks: TLSAsyncTrustSessionHooks(afterTrustConstruction: barrier.block)
    )

    session.start()
    #expect(barrier.waitUntilBlocked())
    session.cancel()
    barrier.release()
    #expect(drain(queue))

    #expect(invocations.count == 0)
    #expect(phases.values.isEmpty)
    #expect(results.count == 0)
  }

  @Test func deadlineBeforeSSLReservationPreventsInvocation() throws {
    let barrier = SessionTestBarrier()
    let invocations = SessionTrustInvocationStore()
    let phases = SessionPhaseRecorder()
    let results = SessionResultRecorder()
    let queue = DispatchQueue(label: "tls-session-race.deadline-first")
    let deadlineQueue = DispatchQueue(label: "tls-session-race.deadline-held")
    deadlineQueue.suspend()
    let session = try makeSession(
      queue: queue,
      invocations: invocations,
      phases: phases,
      results: results,
      deadlineQueue: deadlineQueue,
      timeout: .nanoseconds(0),
      hooks: TLSAsyncTrustSessionHooks(afterTrustConstruction: barrier.block)
    )

    session.start()
    #expect(barrier.waitUntilBlocked())
    deadlineQueue.resume()
    #expect(results.wait(forCount: 1))
    barrier.release()
    #expect(drain(queue))

    #expect(invocations.count == 0)
    #expect(phases.values == [.deadlineExpired])
    #expect(results.count == 1)
    #expect(results.failure == .timedOut)
  }

  @Test func cancelBeforeBasicReservationPreventsBasicInvocation() throws {
    let barrier = SessionTestBarrier()
    let invocations = SessionTrustInvocationStore()
    let phases = SessionPhaseRecorder()
    let results = SessionResultRecorder()
    let queue = DispatchQueue(label: "tls-session-race.basic")
    let session = try makeSession(
      queue: queue,
      invocations: invocations,
      phases: phases,
      results: results,
      hooks: TLSAsyncTrustSessionHooks(beforeBasicReservation: barrier.block)
    )

    session.start()
    #expect(barrier.waitUntilBlocked())
    #expect(invocations.count == 1)
    session.cancel()
    barrier.release()
    #expect(drain(queue))

    #expect(invocations.count == 1)
    #expect(phases.values == [.sslStarted])
    invocations.invokeAll()
    #expect(phases.values == [.sslStarted])
    #expect(results.count == 0)
  }

  @Test func terminalCancellationRejectsAllLatePhaseMutation() throws {
    let invocations = SessionTrustInvocationStore()
    let phases = SessionPhaseRecorder()
    let results = SessionResultRecorder()
    let queue = DispatchQueue(label: "tls-session-race.terminal")
    let session = try makeSession(
      queue: queue,
      invocations: invocations,
      phases: phases,
      results: results
    )

    session.start()
    #expect(invocations.wait(forCount: 2))
    session.cancel()
    let terminalPhases = phases.values
    invocations.invokeAll()
    #expect(drain(queue))

    #expect(terminalPhases == [.sslStarted, .basicStarted])
    #expect(phases.values == terminalPhases)
    #expect(results.count == 0)
  }

  @Test func inlineCallbackCannotOutrunFailedInvocationStatus() throws {
    let phases = SessionPhaseRecorder()
    let result = LocalTLSLatch<Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>>()
    let evaluator = AsyncSecTrustEvaluator { trust, _, callback in
      callback(trust, false, nil)
      return errSecParam
    }
    evaluator.evaluate(
      chain: TLSPeerCertificateChain(certificateDER: [try fixtureDER("rsa-cert")]),
      exactHost: "127.0.0.1",
      phase: phases.record,
      completion: result.resolve
    )

    let resolved = try #require(result.wait(timeout: .seconds(2)))
    switch resolved {
    case .failure(let error): #expect(error == .evaluationStart)
    case .success: Issue.record("failed invocation status produced a snapshot")
    }
    #expect(phases.values == [.sslStarted, .sslCompleted])
  }

  @Test func committedSSLReservationSurvivesCancellationBeforePhysicalInvocation() throws {
    let barrier = SessionTestBarrier()
    let invocations = SessionTrustInvocationStore()
    let phases = SessionPhaseRecorder()
    let results = SessionResultRecorder()
    let queue = DispatchQueue(label: "tls-session-race.reserved")
    let session = try makeSession(
      queue: queue,
      invocations: invocations,
      phases: phases,
      results: results,
      hooks: TLSAsyncTrustSessionHooks(afterReservation: { slot in
        if slot == .ssl { barrier.block() }
      })
    )

    session.start()
    #expect(barrier.waitUntilBlocked())
    #expect(phases.values == [.sslStarted])
    #expect(invocations.count == 0)
    session.cancel()
    barrier.release()
    #expect(drain(queue))

    #expect(invocations.count == 1)
    #expect(phases.values == [.sslStarted])
    #expect(results.count == 0)
    invocations.invokeAll()
    #expect(phases.values == [.sslStarted])
    #expect(results.count == 0)
  }

  private func makeSession(
    queue: DispatchQueue,
    invocations: SessionTrustInvocationStore,
    phases: SessionPhaseRecorder,
    results: SessionResultRecorder,
    deadlineQueue: DispatchQueue? = nil,
    timeout: DispatchTimeInterval = .seconds(2),
    hooks: TLSAsyncTrustSessionHooks = TLSAsyncTrustSessionHooks()
  ) throws -> TLSAsyncTrustSession {
    TLSAsyncTrustSession(
      chain: TLSPeerCertificateChain(certificateDER: [try fixtureDER("rsa-cert")]),
      exactHost: "127.0.0.1",
      evaluationQueue: queue,
      deadlineQueue: deadlineQueue ?? DispatchQueue(label: "tls-session-race.deadline"),
      timeout: timeout,
      evaluateAPI: { trust, evaluationQueue, callback in
        dispatchPrecondition(condition: .onQueue(evaluationQueue))
        invocations.append(trust: trust, callback: callback)
        return errSecSuccess
      },
      phase: phases.record,
      hooks: hooks,
      completion: results.record
    )
  }

  private func drain(_ queue: DispatchQueue) -> Bool {
    let drained = DispatchSemaphore(value: 0)
    queue.async { drained.signal() }
    return drained.wait(timeout: .now() + .seconds(2)) == .success
  }
}

private final class SessionTestBarrier: @unchecked Sendable {
  private let entered = DispatchSemaphore(value: 0)
  private let releaseGate = DispatchSemaphore(value: 0)

  func block() {
    entered.signal()
    _ = releaseGate.wait(timeout: .now() + .seconds(2))
  }

  func waitUntilBlocked() -> Bool {
    entered.wait(timeout: .now() + .seconds(2)) == .success
  }

  func release() { releaseGate.signal() }
}

private final class SessionTrustInvocationStore: @unchecked Sendable {
  typealias Callback = (SecTrust, Bool, CFError?) -> Void

  private let condition = NSCondition()
  private var invocations: [(SecTrust, Callback)] = []

  var count: Int {
    condition.withLock { invocations.count }
  }

  func append(trust: SecTrust, callback: @escaping Callback) {
    condition.withLock {
      invocations.append((trust, callback))
      condition.broadcast()
    }
  }

  func wait(forCount expected: Int) -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date(timeIntervalSinceNow: 2)
    while invocations.count < expected {
      guard condition.wait(until: deadline) else { return false }
    }
    return true
  }

  func invokeAll() {
    let retained = condition.withLock {
      let retained = invocations
      invocations.removeAll()
      return retained
    }
    for (trust, callback) in retained { callback(trust, false, nil) }
  }
}

private final class SessionPhaseRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var phases: [TLSTrustEvaluationPhase] = []
  var values: [TLSTrustEvaluationPhase] { lock.withLock { phases } }
  func record(_ phase: TLSTrustEvaluationPhase) { lock.withLock { phases.append(phase) } }
}

private final class SessionResultRecorder: @unchecked Sendable {
  private let condition = NSCondition()
  private var results = 0
  private var recordedFailure: TLSAsyncTrustEvaluationError?
  var count: Int { condition.withLock { results } }
  var failure: TLSAsyncTrustEvaluationError? { condition.withLock { recordedFailure } }
  func record(_ result: Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>) {
    condition.withLock {
      results += 1
      if case .failure(let error) = result { recordedFailure = error }
      condition.broadcast()
    }
  }

  func wait(forCount expected: Int) -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date(timeIntervalSinceNow: 2)
    while results < expected {
      guard condition.wait(until: deadline) else { return false }
    }
    return true
  }
}
