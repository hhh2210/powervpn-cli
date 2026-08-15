import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2CleanupBudgetTests {
  @Test func shutdownDeadlinesStartFreshAfterStartupBudgetHasExpired() {
    let clock = ProductM2ManualClock()
    let startup = ProductM2AbsoluteBudget.start(clock: clock.clock)
    clock.set(milliseconds: 200_000)
    #expect(!startup.report.hasRemaining)

    let shutdownBudget = ProductM2CleanupBudget.start(clock: clock.clock)
    clock.set(milliseconds: 250_000)
    let shutdown = ProductM2CleanupDeadlines(shutdownBudget)
    #expect(shutdown.controlCleanup.cutoffNanoseconds == 258_000_000_000)
    #expect(shutdown.authorizationCleanup.cutoffNanoseconds == 279_000_000_000)
    #expect(shutdown.verification.cutoffNanoseconds == 303_000_000_000)
    #expect(shutdown.report.cutoffNanoseconds == 305_000_000_000)
    #expect(shutdown.controlCleanup.hasRemaining)
    #expect(shutdown.report.hasRemaining)
  }
}
