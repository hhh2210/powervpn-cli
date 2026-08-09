import Foundation

protocol PortalSleeping: Sendable {
  func sleep(seconds: UInt64) async throws
}

struct ContinuousPortalSleeper: PortalSleeping {
  func sleep(seconds: UInt64) async throws {
    try await Task.sleep(for: .seconds(Int64(seconds)))
  }
}

protocol PortalLogoutBounding: Sendable {
  /// Runs outside the caller's cancellation tree and returns false at the
  /// explicit deadline. The loser is cancelled; no retry is created.
  func run(_ operation: @escaping @Sendable () async -> Void) async -> Bool
}

struct TimedDetachedPortalLogoutBounder: PortalLogoutBounding {
  static let productionTimeoutNanoseconds: UInt64 = 20_000_000_000
  private let timeoutNanoseconds: UInt64

  init(timeoutNanoseconds: UInt64 = Self.productionTimeoutNanoseconds) {
    self.timeoutNanoseconds = max(timeoutNanoseconds, 1)
  }

  func run(_ operation: @escaping @Sendable () async -> Void) async -> Bool {
    await withCheckedContinuation { continuation in
      let gate = PortalLogoutRaceGate(continuation: continuation)
      let operationTask = Task.detached {
        await operation()
        gate.complete(finished: true)
      }
      let timeoutTask = Task.detached { [timeoutNanoseconds] in
        do {
          try await Task.sleep(nanoseconds: timeoutNanoseconds)
          gate.complete(finished: false)
        } catch {}
      }
      gate.install(operationTask, timeoutTask)
    }
  }
}

private final class PortalLogoutRaceGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Bool, Never>?
  private var tasks: [Task<Void, Never>] = []
  private var resolved = false

  init(continuation: CheckedContinuation<Bool, Never>) {
    self.continuation = continuation
  }

  func install(_ operation: Task<Void, Never>, _ timeout: Task<Void, Never>) {
    let shouldCancel = lock.withLock {
      guard !resolved else { return true }
      tasks = [operation, timeout]
      return false
    }
    if shouldCancel {
      operation.cancel()
      timeout.cancel()
    }
  }

  func complete(finished: Bool) {
    let outcome = lock.withLock { () -> (CheckedContinuation<Bool, Never>?, [Task<Void, Never>]) in
      guard !resolved else { return (nil, []) }
      resolved = true
      let saved = continuation
      continuation = nil
      let savedTasks = tasks
      tasks.removeAll()
      return (saved, savedTasks)
    }
    for task in outcome.1 {
      task.cancel()
    }
    outcome.0?.resume(returning: finished)
  }
}

struct PortalWorkflowProgress {
  var loginRequested = false
  var loginAccepted = false
  var sessionCheckRequested = false
  var sessionCheckAccepted = false
  var resourceListRequested = false
  var resourceListAccepted = false
  var logoutRequested = false
  var logoutAccepted = false

  var evidence: PortalOperationEvidence {
    PortalOperationEvidence(
      loginRequested: loginRequested,
      loginAccepted: loginAccepted,
      sessionCheckRequested: sessionCheckRequested,
      sessionCheckAccepted: sessionCheckAccepted,
      resourceListRequested: resourceListRequested,
      resourceListAccepted: resourceListAccepted,
      logoutRequested: logoutRequested,
      logoutAccepted: logoutAccepted
    )
  }
}

final class PortalOwnedMaterialTracker: @unchecked Sendable {
  private let lock = NSLock()
  private var activeRequests: Set<ObjectIdentifier> = []
  private var activeResponses: Set<ObjectIdentifier> = []
  private var requestsErased = true
  private var responsesErased = true

  func beginRequest(_ request: PortalHTTPRequest) {
    _ = lock.withLock { activeRequests.insert(ObjectIdentifier(request)) }
  }

  func beginResponse(_ response: PortalHTTPResponse) {
    _ = lock.withLock { activeResponses.insert(ObjectIdentifier(response)) }
  }

  func observeErasedRequest(_ request: PortalHTTPRequest) {
    let erased =
      (request.requestBody?.count ?? 0) == 0
      && (request.cookieHeader?.count ?? 0) == 0
    lock.withLock {
      guard activeRequests.remove(ObjectIdentifier(request)) != nil else { return }
      requestsErased = requestsErased && erased
    }
  }

  func observeErasedResponse(_ response: PortalHTTPResponse) {
    let erased =
      response.bodyByteCount == 0
      && (response.setCookieByteCount ?? 0) == 0
    lock.withLock {
      guard activeResponses.remove(ObjectIdentifier(response)) != nil else { return }
      responsesErased = responsesErased && erased
    }
  }

  var snapshot: (requests: Bool, responses: Bool) {
    lock.withLock {
      (requestsErased && activeRequests.isEmpty, responsesErased && activeResponses.isEmpty)
    }
  }
}

final class PortalLogoutObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var requested = false
  private var accepted = false
  private var cancelled = false

  func markRequested() { lock.withLock { requested = true } }
  func markAccepted() { lock.withLock { accepted = true } }
  func markCancelled() { lock.withLock { cancelled = true } }

  var snapshot: (requested: Bool, accepted: Bool, cancelled: Bool) {
    lock.withLock { (requested, accepted, cancelled) }
  }
}
