import Foundation

enum NetworkCleanupBudgetError: Error {
  case expired
}

final class NetworkCleanupCommandBudget: @unchecked Sendable {
  private static let nanosecondsPerMillisecond: UInt64 = 1_000_000

  private let lock = NSLock()
  private let monotonicNowNanoseconds: @Sendable () -> UInt64
  private let deadlineNanoseconds: UInt64
  private var lastNowNanoseconds: UInt64
  private var valid: Bool

  init(
    timeoutMilliseconds: Int,
    monotonicNowNanoseconds: @escaping @Sendable () -> UInt64
  ) {
    self.monotonicNowNanoseconds = monotonicNowNanoseconds
    let start = monotonicNowNanoseconds()
    lastNowNanoseconds = start

    guard timeoutMilliseconds >= 0,
      let milliseconds = UInt64(exactly: timeoutMilliseconds)
    else {
      deadlineNanoseconds = 0
      valid = false
      return
    }
    let duration = milliseconds.multipliedReportingOverflow(
      by: Self.nanosecondsPerMillisecond
    )
    let deadline = start.addingReportingOverflow(duration.partialValue)
    deadlineNanoseconds = deadline.partialValue
    valid = !duration.overflow && !deadline.overflow
  }

  func nextCommandTimeoutMilliseconds() -> Int? {
    lock.withLock {
      guard valid else { return nil }
      let now = monotonicNowNanoseconds()
      guard now >= lastNowNanoseconds else {
        valid = false
        return nil
      }
      lastNowNanoseconds = now
      guard now < deadlineNanoseconds else {
        valid = false
        return nil
      }
      let wholeMilliseconds =
        (deadlineNanoseconds - now) / Self.nanosecondsPerMillisecond
      guard wholeMilliseconds > 0 else {
        valid = false
        return nil
      }
      return Int(min(2_000, wholeMilliseconds))
    }
  }
}
