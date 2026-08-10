import Foundation

final class ProductM2PortalAcquisitionStartGate: @unchecked Sendable {
  private let lock = NSLock()
  private var decision: Bool?
  private var waiter: CheckedContinuation<Bool, Never>?

  func waitForStartDecision() async -> Bool {
    await withCheckedContinuation { continuation in
      let immediate = lock.withLock { () -> Bool? in
        if let decision { return decision }
        waiter = continuation
        return nil
      }
      if let immediate {
        continuation.resume(returning: immediate)
      }
    }
  }

  func open(allowProviderStart: Bool) {
    let continuation: CheckedContinuation<Bool, Never>? = lock.withLock {
      guard decision == nil else { return nil }
      decision = allowProviderStart
      let pending = waiter
      waiter = nil
      return pending
    }
    continuation?.resume(returning: allowProviderStart)
  }
}

final class ProductM2PortalAcquisitionCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<ProductM2AuthorizedResourceAcquisition, Never>?
  private var cancelled = false

  /// Linearization: install wins by publishing the task under the same lock
  /// used by cancel. A prior cancel opens the child only onto a closed result.
  func install(
    _ task: Task<ProductM2AuthorizedResourceAcquisition, Never>,
    startGate: ProductM2PortalAcquisitionStartGate
  ) {
    let allowProviderStart = lock.withLock {
      guard !cancelled else { return false }
      self.task = task
      return true
    }
    if !allowProviderStart { task.cancel() }
    startGate.open(allowProviderStart: allowProviderStart)
  }

  func cancel() {
    let task = lock.withLock {
      cancelled = true
      let active = self.task
      self.task = nil
      return active
    }
    task?.cancel()
  }
}
