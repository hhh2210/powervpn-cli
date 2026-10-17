import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// The catalog retry is budget-gated: when the absolute budget cannot fund
/// another full acquisition, the first-attempt classification stands and
/// no second login happens.
@Suite struct CatalogReplayBudgetTests {

  @Test func insufficientAcquisitionBudgetSkipsTheCatalogRetry() async throws {
    let shape = CatalogReplayMatrix.shapes[0]
    let fixture = try authenticatedSnapshot(resourceXML: shape.resourceXML)
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer { support.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let state = AuthorizationLeaseTestState()
    let attempts = ProductM2AuthorizationAttemptQueue([
      ProductM2AuthorizationAttempt(
        source: .nativePortal,
        operation: {
          trace.record("login_1")
          clock.set(milliseconds: 36_000)
          return .acquired(
            source: .nativePortal,
            lease: testAuthorizationLease(
              snapshot: snapshot,
              state: state,
              onClose: { trace.record("logout_1") }
            ),
            serverContactRequested: true
          )
        },
        cancel: {}
      )
    ])

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: support.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in attempts.next() }
      )
    ).run(catalogReplayRequest(), budget: budget)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.automaticRetryCount == 0)
    #expect(report.selectionFailureClass == shape.expectedClass)
    #expect(report.resourceCatalogFailure == shape.expectedFailure)
    #expect(trace.events.filter { $0.hasPrefix("login_") } == ["login_1"])
    #expect(state.closeCount == 1)
  }
}
