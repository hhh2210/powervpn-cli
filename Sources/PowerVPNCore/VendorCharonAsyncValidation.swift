import Foundation

/// Owns one asynchronous boolean validation. Cancellation is terminal: even
/// an uncooperative operation that returns late cannot publish completion.
final class VendorCharonAsyncValidation: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<Void, Never>?

  init(
    operation: @escaping @Sendable () async -> Bool,
    completion: @escaping @Sendable (Bool) -> Void
  ) {
    task = Task {
      let accepted = await operation()
      guard !Task.isCancelled else { return }
      completion(accepted)
    }
  }

  func cancel() {
    let task = lock.withLock { () -> Task<Void, Never>? in
      defer { self.task = nil }
      return self.task
    }
    task?.cancel()
  }
}
