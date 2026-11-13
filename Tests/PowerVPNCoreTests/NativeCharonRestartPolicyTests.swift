import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeCharonRestartPolicyTests {
  private let t0 = Date(timeIntervalSince1970: 1_000_000)

  @Test func restartsOnlyWhenProvablyIdle() {
    var governor = NativeCharonRestartGovernor()
    #expect(governor.request(now: t0, idle: false) == .refuse(.notIdle))
    #expect(governor.request(now: t0, idle: nil) == .refuse(.idleUnknown))
    #expect(governor.request(now: t0, idle: true) == .allow)
  }

  @Test func refusedRequestsDoNotConsumeTheBudget() {
    var governor = NativeCharonRestartGovernor(minimumInterval: 60, budget: 1)
    for _ in 0..<5 { _ = governor.request(now: t0, idle: false) }
    #expect(governor.request(now: t0, idle: true) == .allow)
  }

  @Test func enforcesMinimumIntervalAndWindowBudget() {
    var governor = NativeCharonRestartGovernor(minimumInterval: 60, budget: 2, window: 1_800)
    #expect(governor.request(now: t0, idle: true) == .allow)
    #expect(governor.request(now: t0.addingTimeInterval(30), idle: true) == .refuse(.tooSoon))
    #expect(governor.request(now: t0.addingTimeInterval(90), idle: true) == .allow)
    #expect(
      governor.request(now: t0.addingTimeInterval(200), idle: true) == .refuse(.budgetExhausted))
    // The oldest grant ages out of the window.
    #expect(governor.request(now: t0.addingTimeInterval(1_900), idle: true) == .allow)
  }

  @Test func wakeDetectorSeesTheGapBetweenTheTwoClocks() {
    var detector = NativeWakeDetector(threshold: 20)
    let second: UInt64 = 1_000_000_000
    #expect(
      detector.observe(uptimeNanoseconds: 100 * second, continuousNanoseconds: 500 * second) == nil)
    // 5 s awake, 5 s elapsed: no sleep.
    #expect(
      detector.observe(uptimeNanoseconds: 105 * second, continuousNanoseconds: 505 * second) == nil)
    // 5 s awake but 3605 s elapsed: slept an hour.
    let slept = detector.observe(
      uptimeNanoseconds: 110 * second, continuousNanoseconds: 4_110 * second)
    #expect(slept.map { Int($0) } == 3_600)
    // Clock regression is ignored, not reported.
    #expect(detector.observe(uptimeNanoseconds: 1, continuousNanoseconds: 1) == nil)
  }
}
