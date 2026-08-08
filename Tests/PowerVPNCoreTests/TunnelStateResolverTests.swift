import Testing

@testable import PowerVPNCore

@Test func stoppedHelperCannotReportHealthyFromHistoricalLog() {
  let helper = HelperState(
    state: "exited",
    pid: nil,
    runs: 10,
    successiveCrashes: 9,
    lastTerminatingSignal: "Bus error: 10"
  )
  let historicalState = TunnelLogState(
    health: .healthy,
    latestEvent: "CHILD_SA established"
  )

  let resolved = TunnelStateResolver.resolve(
    helper: helper,
    analyzedLogState: historicalState
  )
  #expect(resolved.health == .stopped)
  #expect(resolved.latestEvent == "helper not running; historical tunnel log ignored")
  #expect(!resolved.historicalHint)
}

@Test func runningHelperCannotPromoteHistoricalLogToCurrentHealth() {
  let helper = HelperState(
    state: "running",
    pid: 123,
    runs: 1,
    successiveCrashes: 0,
    lastTerminatingSignal: nil
  )
  let retrying = TunnelLogState(health: .retrying, latestEvent: "retrying")

  let resolved = TunnelStateResolver.resolve(helper: helper, analyzedLogState: retrying)
  #expect(resolved.health == .unknown)
  #expect(resolved.latestEvent.contains("current helper generation is uncorrelated"))
  #expect(resolved.historicalHint)
}
