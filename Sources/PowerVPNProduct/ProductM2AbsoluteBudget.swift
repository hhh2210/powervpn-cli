import Dispatch
import Foundation

package struct ProductM2MonotonicClock: Sendable {
  private let readNanoseconds: @Sendable () -> UInt64

  package init(nowNanoseconds: @escaping @Sendable () -> UInt64) {
    readNanoseconds = nowNanoseconds
  }

  package func nowNanoseconds() -> UInt64 {
    readNanoseconds()
  }

  package static let continuous = Self {
    DispatchTime.now().uptimeNanoseconds
  }
}

package struct ProductM2StageDeadline: Sendable {
  private static let nanosecondsPerMillisecond: UInt64 = 1_000_000

  private let clock: ProductM2MonotonicClock
  package let cutoffNanoseconds: UInt64

  package init(
    clock: ProductM2MonotonicClock,
    cutoffNanoseconds: UInt64
  ) {
    self.clock = clock
    self.cutoffNanoseconds = cutoffNanoseconds
  }

  package func remainingMilliseconds(cappedAt cap: Int) -> Int? {
    guard cap > 0 else { return nil }
    let now = clock.nowNanoseconds()
    guard cutoffNanoseconds > now else { return nil }
    let raw = (cutoffNanoseconds - now) / Self.nanosecondsPerMillisecond
    guard raw > 0 else { return nil }
    return min(cap, Int(clamping: raw))
  }

  package var hasRemaining: Bool {
    remainingMilliseconds(cappedAt: 1) != nil
  }
}

package struct ProductM2AuthorizationBudget: Sendable {
  package let work: ProductM2StageDeadline
  package let cleanup: ProductM2StageDeadline
  /// A sealed native acquisition performs two independently bounded 15-second
  /// HTTP exchanges (login, then catalog). A retry must be able to fund both.
  package var canStartFullAcquisition: Bool {
    work.remainingMilliseconds(cappedAt: 30_000) == 30_000
  }
}

package struct ProductM2AbsoluteBudget: Sendable {
  package static let totalMilliseconds = 120_000
  package static let workCutoffMilliseconds = 65_000
  package static let controlCleanupCutoffMilliseconds = 73_000
  package static let authorizationCleanupCutoffMilliseconds = 94_000
  package static let verificationCutoffMilliseconds = 118_000
  package static let reportCutoffMilliseconds = 120_000

  package let work: ProductM2StageDeadline
  package let controlCleanup: ProductM2StageDeadline
  package let authorizationCleanup: ProductM2StageDeadline
  package let verification: ProductM2StageDeadline
  package let report: ProductM2StageDeadline

  package var authorization: ProductM2AuthorizationBudget {
    ProductM2AuthorizationBudget(work: work, cleanup: authorizationCleanup)
  }

  package static func start(
    clock: ProductM2MonotonicClock = .continuous
  ) -> Self {
    Self(startNanoseconds: clock.nowNanoseconds(), clock: clock)
  }

  package init(
    startNanoseconds: UInt64,
    clock: ProductM2MonotonicClock
  ) {
    work = Self.deadline(
      after: Self.workCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: clock
    )
    controlCleanup = Self.deadline(
      after: Self.controlCleanupCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: clock
    )
    authorizationCleanup = Self.deadline(
      after: Self.authorizationCleanupCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: clock
    )
    verification = Self.deadline(
      after: Self.verificationCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: clock
    )
    report = Self.deadline(
      after: Self.reportCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: clock
    )
  }

  private static func deadline(
    after milliseconds: Int,
    startNanoseconds: UInt64,
    clock: ProductM2MonotonicClock
  ) -> ProductM2StageDeadline {
    let delta = UInt64(milliseconds).multipliedReportingOverflow(by: 1_000_000)
    let cutoff: UInt64
    if delta.overflow {
      cutoff = .max
    } else {
      let sum = startNanoseconds.addingReportingOverflow(delta.partialValue)
      cutoff = sum.overflow ? .max : sum.partialValue
    }
    return ProductM2StageDeadline(clock: clock, cutoffNanoseconds: cutoff)
  }
}
