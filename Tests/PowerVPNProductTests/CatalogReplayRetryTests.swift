import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Retry and exhaustion replay: every synthetic catalog-rejection shape
/// drives the real acquisition pipeline through login accepted → catalog
/// rejected → exactly one fresh-login retry. The server-side trigger of
/// the live intermittent rejection is unresolved (see docs/ci.md); these
/// tests pin the client-side retry state machine, not any server
/// behavior claim.
@Suite struct CatalogReplayRetryTests {

  @Test(arguments: CatalogReplayMatrix.shapeIDs)
  func catalogReplayRetriesOnceWithFreshSessionThenSucceeds(
    _ shapeID: String
  ) async throws {
    let shape = try #require(CatalogReplayMatrix.shape(id: shapeID))
    let report = try await replayCatalogShape(shape, secondCatalog: .healthy)

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.automaticRetryCount == 1)
    #expect(report.selectionFailureClass == nil)
    #expect(report.resourceCatalogFailure == nil)
    try assertCatalogReplayValueFree(report, shape: shape)
  }

  @Test(arguments: CatalogReplayMatrix.shapeIDs)
  func catalogReplayExhaustsAfterExactlyOneRetryWithTruthfulTokens(
    _ shapeID: String
  ) async throws {
    let shape = try #require(CatalogReplayMatrix.shape(id: shapeID))
    let report = try await replayCatalogShape(shape, secondCatalog: .rejected)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.firstBadEvent == .resourceCatalogRejected)
    #expect(report.automaticRetryCount == 1)
    #expect(report.selectionFailureClass == shape.expectedClass)
    #expect(report.resourceCatalogFailure == shape.expectedFailure)
    try assertCatalogReplayValueFree(report, shape: shape)

    let object = try #require(
      JSONSerialization.jsonObject(
        with: JSONEncoder().encode(report)
      ) as? [String: Any])
    #expect(
      object["selectionFailureClass"] as? String == shape.expectedClass.rawValue)
    if let expected = shape.expectedFailure {
      let failure = try #require(
        object["resourceCatalogFailure"] as? [String: Any])
      #expect(failure["stage"] as? String == expected.stage.rawValue)
      #expect(
        failure["failureClass"] as? String == expected.failureClass.rawValue)
      if let ordinal = expected.resourceOrdinal {
        #expect(failure["resourceOrdinal"] as? Int == ordinal)
      } else {
        #expect(failure["resourceOrdinal"] == nil)
      }
      if let fieldPath = expected.fieldPath {
        #expect(failure["fieldPath"] as? String == fieldPath)
      } else {
        #expect(failure["fieldPath"] == nil)
      }
    } else {
      #expect(object["resourceCatalogFailure"] == nil)
    }
    #expect(object["automaticRetryCount"] as? Int == 1)
  }

  @Test func rejectedFreshLoginKeepsFirstLogoutAndReportsTheRejection()
    async throws
  {
    let shape = CatalogReplayMatrix.shapes[0]
    let fixture = try authenticatedSnapshot(resourceXML: shape.resourceXML)
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer { support.erase() }
    let trace = ProductM2TestTrace()
    let state = AuthorizationLeaseTestState()
    let attempts = ProductM2AuthorizationAttemptQueue([
      ProductM2AuthorizationAttempt(
        source: .nativePortal,
        operation: {
          trace.record("login_1")
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
      ),
      ProductM2AuthorizationAttempt(
        source: .nativePortal,
        operation: {
          trace.record("login_2")
          return .rejected(
            source: .nativePortal,
            failure: .providerUnavailable,
            cleanup: ProductM2AuthorizationCloseReceipt(
              outcome: .notRequired,
              ownedMaterialErased: true,
              sourceCloseRequested: false,
              serverContactRequested: true
            )
          )
        },
        cancel: {}
      ),
    ])

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: support.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in attempts.next() }
      )
    ).run(catalogReplayRequest())

    #expect(report.outcome == .authorizationAcquisitionRejected)
    #expect(report.authorizationFailure == .providerUnavailable)
    #expect(report.automaticRetryCount == 1)
    #expect(report.cleanupVerified)
    #expect(state.closeCount == 1)
    #expect(
      trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
        == ["login_1", "logout_1", "login_2"])
  }
}
