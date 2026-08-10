import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupAbsoluteBudgetTests {
  @Test func captureShrinksTimeoutsAndStartsNothingAfterDeadline() async {
    let clock = ManualNetworkCleanupClock(nanoseconds: 1_000_000_000)
    let runner = BudgetFixtureNetworkCleanupRunner(
      networkCleanupSuccessfulResponses(),
      afterRun: { clock.advance(milliseconds: 1_000) }
    )

    let snapshot = await InstalledNetworkCleanupObserver(
      runner: runner,
      monotonicNowNanoseconds: clock.now
    ).capture(
      window: NetworkCleanupCaptureWindow(),
      selectedRoutes: nil,
      timeoutMilliseconds: 4_000
    )

    #expect(
      runner.commands == [
        .helperGeneration, .surgeProcesses, .defaultRoute, .dns,
      ])
    #expect(runner.timeouts == [2_000, 2_000, 2_000, 1_000])
    #expect(snapshot == .unavailable(.commandFailed))
  }

  @Test func zeroAndOverflowBudgetsStartNoCommand() async {
    let zeroClock = ManualNetworkCleanupClock(nanoseconds: 10_000_000)
    let zeroRunner = BudgetFixtureNetworkCleanupRunner(
      networkCleanupSuccessfulResponses()
    )
    let zero = await InstalledNetworkCleanupObserver(
      runner: zeroRunner,
      monotonicNowNanoseconds: zeroClock.now
    ).capture(
      window: NetworkCleanupCaptureWindow(),
      selectedRoutes: nil,
      timeoutMilliseconds: 0
    )

    let overflowClock = ManualNetworkCleanupClock(
      nanoseconds: UInt64.max - 500_000
    )
    let overflowRunner = BudgetFixtureNetworkCleanupRunner(
      networkCleanupSuccessfulResponses()
    )
    let overflow = await InstalledNetworkCleanupObserver(
      runner: overflowRunner,
      monotonicNowNanoseconds: overflowClock.now
    ).capture(
      window: NetworkCleanupCaptureWindow(),
      selectedRoutes: nil,
      timeoutMilliseconds: 1
    )

    #expect(zeroRunner.commands.isEmpty)
    #expect(overflowRunner.commands.isEmpty)
    #expect(zero == .unavailable(.commandFailed))
    #expect(overflow == .unavailable(.commandFailed))
  }

  @Test func regressingMonotonicClockFailsClosedBeforeNextCommand() async {
    let initial: UInt64 = 2_000_000_000
    let clock = ManualNetworkCleanupClock(nanoseconds: initial)
    let runner = BudgetFixtureNetworkCleanupRunner(
      networkCleanupSuccessfulResponses(),
      afterRun: { clock.set(nanoseconds: initial - 1) }
    )

    let snapshot = await InstalledNetworkCleanupObserver(
      runner: runner,
      monotonicNowNanoseconds: clock.now
    ).capture(
      window: NetworkCleanupCaptureWindow(),
      selectedRoutes: nil,
      timeoutMilliseconds: 5_000
    )

    #expect(runner.commands == [.helperGeneration])
    #expect(runner.timeouts == [2_000])
    #expect(snapshot == .unavailable(.commandFailed))
  }
}

private final class ManualNetworkCleanupClock: @unchecked Sendable {
  private let lock = NSLock()
  private var nanoseconds: UInt64

  init(nanoseconds: UInt64) {
    self.nanoseconds = nanoseconds
  }

  func now() -> UInt64 {
    lock.withLock { nanoseconds }
  }

  func advance(milliseconds: UInt64) {
    lock.withLock { nanoseconds += milliseconds * 1_000_000 }
  }

  func set(nanoseconds: UInt64) {
    lock.withLock { self.nanoseconds = nanoseconds }
  }
}

private final class BudgetFixtureNetworkCleanupRunner: @unchecked Sendable,
  NetworkCleanupCommandRunning
{
  private let lock = NSLock()
  private let afterRun: @Sendable () -> Void
  private var responses: [NetworkCleanupCommand: [BoundedCommandResult]]
  private var storedCommands: [NetworkCleanupCommand] = []
  private var storedTimeouts: [Int] = []

  init(
    _ responses: [NetworkCleanupCommand: [BoundedCommandResult]],
    afterRun: @escaping @Sendable () -> Void = {}
  ) {
    self.responses = responses
    self.afterRun = afterRun
  }

  func run(
    _ command: NetworkCleanupCommand,
    timeoutMilliseconds: Int
  ) async -> BoundedCommandResult {
    let result = lock.withLock {
      storedCommands.append(command)
      storedTimeouts.append(timeoutMilliseconds)
      guard var queue = responses[command], !queue.isEmpty else {
        return BoundedCommandResult.immediate(.launchFailed)
      }
      let result = queue.removeFirst()
      responses[command] = queue
      return result
    }
    afterRun()
    return result
  }

  var commands: [NetworkCleanupCommand] { lock.withLock { storedCommands } }
  var timeouts: [Int] { lock.withLock { storedTimeouts } }
}
