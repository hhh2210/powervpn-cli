import Foundation

final class PortalRequestCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<PortalHTTPResponse, Error>?
  private var cancelled = false

  func install(_ task: Task<PortalHTTPResponse, Error>) {
    let cancelImmediately = lock.withLock {
      guard !cancelled else { return true }
      self.task = task
      return false
    }
    if cancelImmediately { task.cancel() }
  }

  func cancel() {
    let task = lock.withLock {
      cancelled = true
      let installed = task
      self.task = nil
      return installed
    }
    task?.cancel()
  }
}

final class PortalRequestCancellationRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var requests: [ObjectIdentifier: PortalRequestCancellation] = [:]

  func register(_ request: PortalRequestCancellation) {
    lock.withLock { requests[ObjectIdentifier(request)] = request }
  }

  func unregister(_ request: PortalRequestCancellation) {
    _ = lock.withLock { requests.removeValue(forKey: ObjectIdentifier(request)) }
  }

  func cancel(_ request: PortalRequestCancellation) {
    _ = lock.withLock { requests.removeValue(forKey: ObjectIdentifier(request)) }
    request.cancel()
  }

  func cancelAll() {
    let active = lock.withLock {
      let active = Array(requests.values)
      requests.removeAll()
      return active
    }
    for request in active { request.cancel() }
  }
}
