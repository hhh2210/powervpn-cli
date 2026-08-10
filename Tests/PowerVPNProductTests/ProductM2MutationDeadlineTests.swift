import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2MutationDeadlineTests {
  @Test func snapshotBorrowCannotUseAStaleRelativeStartTimeout() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: snapshot,
        trace: trace,
        authorizationPrepare: { handle, target in
          try wrappedPreparedResource(
            snapshot: snapshot,
            handle: handle,
            target: target,
            behavior: .invokeOnce,
            beforeInvocation: { clock.set(milliseconds: 65_000) }
          )
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(report.startOutcome == .notAttempted)
    #expect(!report.helperMutationRequested)
    #expect(report.cleanupVerified)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 1)
  }
}
