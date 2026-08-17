import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Non-catalog selection failures must never consume the fresh-login
/// retry: it is reserved for catalog-class rejections.
@Suite struct CatalogReplayNonCatalogTests {

  @Test func resourceNotFoundNeverRetries() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML(["other-resource"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let trace = ProductM2TestTrace()
    let state = AuthorizationLeaseTestState()

    let report = try await catalogReplaySingleAttemptRun(
      lease: testAuthorizationLease(
        snapshot: snapshot,
        state: state,
        onClose: { trace.record("logout_1") }
      ),
      trace: trace
    )

    #expect(report.outcome == .resourceNotFound)
    #expect(report.automaticRetryCount == 0)
    #expect(report.selectionFailureClass == nil)
    #expect(trace.events.filter { $0.hasPrefix("login_") } == ["login_1"])
    #expect(state.closeCount == 1)
  }

  @Test func selectionReplayNeverRetries() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML([CatalogReplayMatrix.requestedDisplayName]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let state = AuthorizationLeaseTestState()
    let lease = testAuthorizationLease(snapshot: snapshot, state: state)
    _ = try await lease.selectUnique(
      displayName: CatalogReplayMatrix.requestedDisplayName,
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )
    let trace = ProductM2TestTrace()

    let report = try await catalogReplaySingleAttemptRun(lease: lease, trace: trace)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .selectionReplay)
    #expect(report.automaticRetryCount == 0)
    #expect(trace.events.filter { $0.hasPrefix("login_") } == ["login_1"])
  }

  @Test func prepareRemapNeverRetries() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML([CatalogReplayMatrix.requestedDisplayName]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let trace = ProductM2TestTrace()

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: snapshot,
        trace: trace,
        authorizationPrepare: { handle, target in
          snapshot.erase()
          return try ProductM2PortalAdapter.prepare(
            snapshot: snapshot,
            handle: handle,
            requiredTargetIPv4: target
          )
        }
      )
    ).run(catalogReplayRequest())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .prepareRemap)
    #expect(report.resourceCatalogFailure?.failureClass == .snapshotInaccessible)
    #expect(report.automaticRetryCount == 0)
    #expect(trace.count("acquire") == 1)
  }
}
