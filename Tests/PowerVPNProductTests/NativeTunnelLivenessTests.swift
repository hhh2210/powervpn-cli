import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNProduct

@Suite struct NativeTunnelLossDetectorTests {
  /// Whether each probe result, fed in order, confirmed the loss.
  private func verdicts(_ results: [NativeTunnelLiveness], threshold: Int = 3) -> [Bool] {
    var detector = NativeTunnelLossDetector(threshold: threshold)
    return results.map { detector.observe($0) }
  }

  @Test func confirmsLossOnlyAfterAnUninterruptedRunOfAbsentResults() {
    #expect(verdicts([.absent, .absent, .absent]) == [false, false, true])
    #expect(verdicts([.installed, .absent, .absent]) == [false, false, false])
  }

  @Test(arguments: [NativeTunnelLiveness.unknown, .installed])
  func anyOtherResultRestartsTheCount(_ interruption: NativeTunnelLiveness) {
    #expect(
      verdicts([.absent, .absent, interruption, .absent, .absent, .absent])
        == [false, false, false, false, false, true])
    var detector = NativeTunnelLossDetector(threshold: 3)
    _ = detector.observe(.absent)
    _ = detector.observe(interruption)
    #expect(detector.consecutiveAbsent == 0)
  }

  @Test func anUnreachableCharonNeverConfirmsLoss() {
    #expect(!verdicts(Array(repeating: .unknown, count: 1_000)).contains(true))
  }

  @Test func aThresholdBelowOneStillNeedsOneAbsentResult() {
    #expect(verdicts([.unknown, .absent], threshold: 0) == [false, true])
  }
}

@Suite struct NativeTunnelLivenessClassificationTests {
  private static let own = "powervpn-thu21-0a1b2c3d"

  private func summary(_ name: String, children: [String]) -> NativeIKESummary {
    NativeIKESummary(
      name: name, state: "ESTABLISHED", remoteHost: nil, localVirtualIPs: [],
      childStates: children)
  }

  private func classify(_ summaries: [NativeIKESummary]?) -> NativeTunnelLiveness {
    .classify(summaries) { $0 == Self.own }
  }

  @Test func aFailedQueryProvesNothing() {
    #expect(classify(nil) == .unknown)
  }

  @Test func anAnswerWithoutTheSessionIsAbsence() {
    #expect(classify([]) == .absent)
    #expect(classify([summary("powervpn-thu52-ffffffff", children: ["INSTALLED"])]) == .absent)
  }

  @Test func anInstalledChildOnAnySAOfTheSessionIsAlive() {
    #expect(classify([summary(Self.own, children: ["INSTALLED"])]) == .installed)
    // A reauthentication lists the old and the new SA under one name.
    #expect(
      classify([summary(Self.own, children: []), summary(Self.own, children: ["INSTALLED"])])
        == .installed)
  }

  @Test(arguments: [[], ["REKEYING"], ["CREATED"], ["DELETING"]])
  func anSAWithoutAnInstalledChildIsNotAbsence(_ children: [String]) {
    #expect(classify([summary(Self.own, children: children)]) == .unknown)
  }

  @Test func theTargetProbeMatchesByPrefixAndFailsToUnknown() async {
    // No VICI socket at this path: the probe must not report absence.
    #expect(await NativeTunnel.liveness(target: "thu21", vici: "/synthetic-unused") == .unknown)
    #expect(NativeTunnel.liveness(vici: "/synthetic-unused") { _ in true } == .unknown)
  }
}

@Suite struct ProxyTunnelWatchdogTests {
  private static let policy = ProxyTunnelWatchPolicy(
    interval: .milliseconds(2), absentThreshold: 3)

  private func runProxy(
    lease: ProxyTestLease, child: any ProxyChildRunning
  ) async throws -> ProxyCommandResult {
    try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: child,
      watchPolicy: Self.policy,
      runtime: proxyOpen(lease: lease)
    )
  }

  @Test func confirmedLossStopsTheChildThenRunsTheNormalShutdown() async throws {
    let lease = ProxyTestLease(liveness: [.installed, .absent, .absent, .absent])
    let child = ProxyGatedChildRunner()

    let result = try await runProxy(lease: lease, child: child)

    #expect(child.wasCancelled)
    #expect(result.exitCode == 70)
    #expect(result.standardError == "tunnel_lost\n")
    #expect(lease.recordedEvents == ["permit:3221226005", "lost:3", "shutdown"])
  }

  @Test(arguments: [
    [NativeTunnelLiveness.unknown],
    [.absent, .absent, .unknown],
    [.absent, .installed],
    [.absent, .absent, .installed],
    [.installed],
  ])
  func theChildKeepsRunningWithoutConfirmedLoss(_ script: [NativeTunnelLiveness]) async throws {
    let lease = ProxyTestLease(liveness: script)
    let child = ProxyGatedChildRunner()

    async let pending = runProxy(lease: lease, child: child)
    // Far more probes than the threshold, several times through the script.
    let deadline = ContinuousClock.now + .seconds(5)
    while lease.probeCount < 20, ContinuousClock.now < deadline {
      try await Task.sleep(for: .milliseconds(2))
    }
    #expect(lease.probeCount >= 20)
    #expect(!child.wasCancelled)
    child.release()
    let result = try await pending

    #expect(!child.wasCancelled)
    #expect(result.exitCode == 0)
    #expect(result.standardError.isEmpty)
    #expect(lease.recordedEvents == ["permit:3221226005", "shutdown"])
  }

  @Test func aBackendWithoutAProbeIsNotWatched() async throws {
    let lease = ProxyTestLease()
    let child = ProxyTestChildRunner(outcome: .exited(0))

    let result = try await runProxy(lease: lease, child: child)

    #expect(result.exitCode == 0)
    #expect(lease.probeCount == 0)
    #expect(lease.recordedEvents == ["permit:3221226005", "shutdown"])
  }

  @Test func aChildThatEndsFirstWinsOverALossConfirmedMeanwhile() async throws {
    // The child exits on its own at once; the watchdog may or may not get a
    // probe in, but the session's own result is what is reported.
    let lease = ProxyTestLease(liveness: [.absent])
    let child = ProxyTestChildRunner(outcome: .exited(0))

    let result = try await runProxy(lease: lease, child: child)

    #expect(result.exitCode == 0)
    #expect(result.standardError.isEmpty)
  }
}
