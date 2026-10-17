import Foundation

/// One-shot flag an async test can await without parking a cooperative
/// thread. Waiting on a DispatchSemaphore from an async test holds the very
/// thread the awaited task needs; on small CI runners that turns into
/// timeouts or a hung test run.
final class AsyncTestSignal: @unchecked Sendable {
  private let lock = NSLock()
  private var raised = false

  func signal() { lock.withLock { raised = true } }

  func wait(timeout: Duration = .seconds(2)) async -> Bool {
    let deadline = ContinuousClock.now + timeout
    while !lock.withLock({ raised }) {
      guard ContinuousClock.now < deadline else { return false }
      try? await Task.sleep(for: .milliseconds(5))
    }
    return true
  }
}
