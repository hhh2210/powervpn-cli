import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Shared harness for the CatalogReplay suites: drives the real
/// acquisition pipeline (`ProductM2ConnectOnceCoordinator` +
/// `productM2TestDependencies`) with two scripted login attempts so a
/// first-attempt catalog rejection can be followed by the exactly-one
/// fresh-login retry. All offline; deterministic (manual clock / default
/// test budget only).
enum CatalogReplaySecondCatalog {
  case healthy
  case rejected
}

func catalogReplayRequest() -> ProductM2ConnectRequest {
  ProductM2ConnectRequest(
    resourceDisplayName: CatalogReplayMatrix.requestedDisplayName,
    sshTarget: .thu21
  )
}

/// First attempt serves `shape.resourceXML`; the fresh-login retry serves
/// a healthy catalog (`.healthy`) or the same rejected shape
/// (`.rejected`). Returns the final report; asserts the login/logout
/// event sequence `login_1, logout_1, login_2, logout_2` (first session
/// logged out before the re-login).
func replayCatalogShape(
  _ shape: CatalogReplayShape,
  secondCatalog: CatalogReplaySecondCatalog
) async throws -> ProductM2ConnectReport {
  let first = try authenticatedSnapshot(
    cookie: CatalogReplayMatrix.snapshotCookie(
      shapeID: shape.label, attempt: "first"),
    resourceXML: shape.resourceXML
  )
  let secondXML: String
  switch secondCatalog {
  case .healthy:
    secondXML = m2ResourceXML([CatalogReplayMatrix.requestedDisplayName])
  case .rejected:
    secondXML = shape.resourceXML
  }
  let second = try authenticatedSnapshot(
    cookie: CatalogReplayMatrix.snapshotCookie(
      shapeID: shape.label, attempt: "retry"),
    resourceXML: secondXML
  )
  let support = try authenticatedSnapshot(
    cookie: CatalogReplayMatrix.snapshotCookie(
      shapeID: shape.label, attempt: "support"),
    resourceXML: m2ResourceXML(["support-only"])
  )
  defer {
    first.erase()
    second.erase()
    support.erase()
  }
  let trace = ProductM2TestTrace()
  let firstState = AuthorizationLeaseTestState()
  let secondState = AuthorizationLeaseTestState()
  let firstSnapshot = first.snapshot
  let secondSnapshot = second.snapshot
  let attempts = ProductM2AuthorizationAttemptQueue([
    ProductM2AuthorizationAttempt(
      source: .nativePortal,
      operation: {
        trace.record("login_1")
        return .acquired(
          source: .nativePortal,
          lease: testAuthorizationLease(
            snapshot: firstSnapshot,
            state: firstState,
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
        return .acquired(
          source: .nativePortal,
          lease: testAuthorizationLease(
            snapshot: secondSnapshot,
            state: secondState,
            onClose: { trace.record("logout_2") }
          ),
          serverContactRequested: true
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

  #expect(
    trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
      == ["login_1", "logout_1", "login_2", "logout_2"])
  return report
}

/// One scripted login attempt (no retry expected); records `login_1`.
func catalogReplaySingleAttemptRun(
  lease: ProductM2AuthorizedResourceLease,
  trace: ProductM2TestTrace
) async throws -> ProductM2ConnectReport {
  let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
  defer { support.erase() }
  return await ProductM2ConnectOnceCoordinator(
    dependencies: productM2TestDependencies(
      snapshot: support.snapshot,
      trace: trace,
      beginAuthorizationOverride: { _ in
        ProductM2AuthorizationAttempt(
          source: .nativePortal,
          operation: {
            trace.record("login_1")
            return .acquired(
              source: .nativePortal,
              lease: lease,
              serverContactRequested: true
            )
          },
          cancel: {}
        )
      }
    )
  ).run(catalogReplayRequest())
}

func assertCatalogReplayValueFree(
  _ report: ProductM2ConnectReport,
  shape: CatalogReplayShape
) throws {
  let encoded = try #require(
    String(data: JSONEncoder().encode(report), encoding: .utf8))
  let described = String(describing: report)
  let sentinels =
    CatalogReplayMatrix.universalSentinels
    + CatalogReplayMatrix.snapshotSentinels(shapeID: shape.label)
    + shape.rawFailureValues
  for sentinel in sentinels {
    #expect(!encoded.contains(sentinel))
    #expect(!described.contains(sentinel))
  }
}
