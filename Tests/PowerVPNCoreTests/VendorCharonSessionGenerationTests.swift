import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonSessionGenerationTests {
  @Test func acceptsOnlyExactColdToSingleRunningTransition() {
    let cold = snapshot(running: false, pid: nil, runs: 19)
    let running = snapshot(running: true, pid: 41, runs: 20)

    #expect(
      VendorCharonSessionGenerationValidator.validate(
        before: cold,
        current: running
      ))
    #expect(
      !VendorCharonSessionGenerationValidator.validate(
        before: cold,
        current: snapshot(running: true, pid: 41, runs: 21)
      ))
    #expect(
      !VendorCharonSessionGenerationValidator.validate(
        before: running,
        current: running
      ))
    #expect(
      !VendorCharonSessionGenerationValidator.validate(
        before: cold,
        current: snapshot(running: false, pid: nil, runs: 20)
      ))
  }

  private func snapshot(
    running: Bool,
    pid: Int?,
    runs: Int
  ) -> VendorHelperGenerationSnapshot {
    VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: running,
      inactiveConfirmed: !running,
      activeCount: running ? 1 : 0,
      pid: pid,
      runs: runs
    )
  }
}
