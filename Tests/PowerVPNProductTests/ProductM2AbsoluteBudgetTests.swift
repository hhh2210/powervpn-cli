import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2AbsoluteBudgetTests {
  @Test func exactCutoffsShareOneMonotonicStart() {
    let clock = ProductM2ManualClock(nowNanoseconds: 7_000_000)
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)

    #expect(budget.work.cutoffNanoseconds == 65_007_000_000)
    #expect(budget.controlCleanup.cutoffNanoseconds == 73_007_000_000)
    #expect(budget.authorizationCleanup.cutoffNanoseconds == 94_007_000_000)
    #expect(budget.verification.cutoffNanoseconds == 118_007_000_000)
    #expect(budget.report.cutoffNanoseconds == 120_007_000_000)
    #expect(budget.authorization.work.cutoffNanoseconds == budget.work.cutoffNanoseconds)
    #expect(
      budget.authorization.cleanup.cutoffNanoseconds
        == budget.authorizationCleanup.cutoffNanoseconds)
  }

  @Test func remainingFloorsCapsAndNeverStartsBelowOneMillisecond() {
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)

    #expect(budget.work.remainingMilliseconds(cappedAt: 2_000) == 2_000)
    #expect(budget.work.remainingMilliseconds(cappedAt: 0) == nil)
    clock.set(milliseconds: 64_999)
    #expect(budget.work.remainingMilliseconds(cappedAt: 2_000) == 1)
    clock.advance(nanoseconds: 1)
    #expect(budget.work.remainingMilliseconds(cappedAt: 2_000) == nil)
    #expect(!budget.work.hasRemaining)
    #expect(budget.controlCleanup.remainingMilliseconds(cappedAt: 20_000) == 8_000)
    #expect(budget.authorizationCleanup.remainingMilliseconds(cappedAt: 20_000) == 20_000)
    #expect(budget.verification.remainingMilliseconds(cappedAt: 24_000) == 24_000)
    #expect(budget.report.remainingMilliseconds(cappedAt: 2_000) == 2_000)
  }

  @Test func cutoffArithmeticSaturatesInsteadOfWrapping() {
    let start = UInt64.max - 500_000
    let clock = ProductM2ManualClock(nowNanoseconds: start)
    let budget = ProductM2AbsoluteBudget(
      startNanoseconds: start,
      clock: clock.clock
    )

    #expect(budget.work.cutoffNanoseconds == UInt64.max)
    #expect(budget.report.cutoffNanoseconds == UInt64.max)
    #expect(budget.report.remainingMilliseconds(cappedAt: 2_000) == nil)
  }
}

final class ProductM2ManualClock: @unchecked Sendable {
  private let lock = NSLock()
  private var now: UInt64
  private var queuedReads: [UInt64] = []

  init(nowNanoseconds: UInt64 = 0) {
    now = nowNanoseconds
  }

  var clock: ProductM2MonotonicClock {
    ProductM2MonotonicClock {
      self.lock.withLock {
        guard !self.queuedReads.isEmpty else { return self.now }
        self.now = self.queuedReads.removeFirst()
        return self.now
      }
    }
  }

  func set(milliseconds: UInt64) {
    lock.withLock { now = milliseconds * 1_000_000 }
  }

  func advance(nanoseconds: UInt64) {
    lock.withLock {
      let result = now.addingReportingOverflow(nanoseconds)
      now = result.overflow ? .max : result.partialValue
    }
  }

  func enqueue(milliseconds: [UInt64]) {
    lock.withLock {
      queuedReads.append(contentsOf: milliseconds.map { $0 * 1_000_000 })
    }
  }
}
