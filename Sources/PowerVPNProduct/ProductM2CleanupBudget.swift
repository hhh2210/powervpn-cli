import Foundation

/// Shutdown budget configuration. Its deadlines are anchored only when cleanup
/// starts, so constructing it alongside a long-lived tunnel cannot stale it.
package struct ProductM2CleanupBudget: Sendable {
  package static let controlCleanupCutoffMilliseconds = 8_000
  package static let authorizationCleanupCutoffMilliseconds = 29_000
  package static let verificationCutoffMilliseconds = 53_000
  package static let reportCutoffMilliseconds = 55_000

  fileprivate let clock: ProductM2MonotonicClock

  package static func start(
    clock: ProductM2MonotonicClock = .continuous
  ) -> Self {
    Self(clock: clock)
  }
}

struct ProductM2CleanupDeadlines: Sendable {
  let controlCleanup: ProductM2StageDeadline
  let authorizationCleanup: ProductM2StageDeadline
  let verification: ProductM2StageDeadline
  let report: ProductM2StageDeadline

  init(_ budget: ProductM2AbsoluteBudget) {
    controlCleanup = budget.controlCleanup
    authorizationCleanup = budget.authorizationCleanup
    verification = budget.verification
    report = budget.report
  }

  init(_ budget: ProductM2CleanupBudget) {
    let startNanoseconds = budget.clock.nowNanoseconds()
    controlCleanup = Self.deadline(
      after: ProductM2CleanupBudget.controlCleanupCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: budget.clock
    )
    authorizationCleanup = Self.deadline(
      after: ProductM2CleanupBudget.authorizationCleanupCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: budget.clock
    )
    verification = Self.deadline(
      after: ProductM2CleanupBudget.verificationCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: budget.clock
    )
    report = Self.deadline(
      after: ProductM2CleanupBudget.reportCutoffMilliseconds,
      startNanoseconds: startNanoseconds,
      clock: budget.clock
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
