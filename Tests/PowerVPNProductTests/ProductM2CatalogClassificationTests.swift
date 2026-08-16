import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2CatalogClassificationTests {
  @Test func initialIntegerFailureCarriesExactValueFreeClassifier() async throws {
    let sentinel = "server-value-must-not-escape"
    let xml = m2ResourceXML(["server-display-must-not-escape"])
      .replacingOccurrences(of: "port=\"500\"", with: "port=\"\(sentinel)\"")
    let fixture = try authenticatedSnapshot(resourceXML: xml)
    defer { fixture.erase() }

    let report = await catalogReport(snapshot: fixture.snapshot)

    #expect(report.schemaVersion == 15)
    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.firstBadEvent == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .catalogMapping)
    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .integerInvalid,
          resourceOrdinal: 1,
          fieldPath: "common.ike_port"
        ))
    try assertValueFree(report, sentinels: [sentinel, "server-display-must-not-escape"])
    let encoded = try JSONEncoder().encode(report)
    let object = try #require(
      JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    let failure = try #require(object["resourceCatalogFailure"] as? [String: Any])
    #expect(Set(failure.keys) == ["stage", "failureClass", "resourceOrdinal", "fieldPath"])
    #expect(object["selectionFailureClass"] as? String == "catalog_mapping")
  }

  @Test func missingResourceListCarriesScopeClassifier() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/></INTERGRATION_INFO></ROOT>"
    )
    defer { fixture.erase() }

    let report = await catalogReport(snapshot: fixture.snapshot)

    #expect(report.selectionFailureClass == .catalogMapping)
    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .scope,
          failureClass: .resourceListMissing,
          resourceOrdinal: nil,
          fieldPath: nil
        ))
  }

  @Test func validEmptyCatalogIsDistinctFromMappingFailure() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML([]))
    defer { fixture.erase() }

    let report = await catalogReport(snapshot: fixture.snapshot)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .catalogEmpty)
    #expect(report.resourceCatalogFailure == nil)
  }

  @Test func invalidCatalogInvariantIsDistinctAndNeverPrepares() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let candidate = try #require(
      ProductM2PortalAdapter.catalog(snapshot: fixture.snapshot).first)
    let trace = ProductM2TestTrace()
    let lease = classifiedLease(
      snapshot: fixture.snapshot,
      catalog: { [candidate, candidate] },
      prepare: { _, _ in
        trace.record("prepare")
        throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
      }
    )

    let report = try await report(using: lease)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .catalogInvariantInvalid)
    #expect(report.resourceCatalogFailure == nil)
    #expect(trace.count("prepare") == 0)
  }

  @Test func secondMapFailureIsPrepareRemap() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
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
    ).run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .prepareRemap)
    #expect(report.resourceCatalogFailure?.stage == .scope)
    #expect(report.resourceCatalogFailure?.failureClass == .snapshotInaccessible)
    #expect(report.resourceCatalogFailure?.resourceOrdinal == nil)
    #expect(report.resourceCatalogFailure?.fieldPath == nil)
  }

  @Test func selectionReplayIsReportedWithoutCatalogDetails() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    let lease = testAuthorizationLease(snapshot: fixture.snapshot, state: state)
    _ = try await lease.selectUnique(
      displayName: "Campus NC",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )

    let report = try await report(using: lease)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .selectionReplay)
    #expect(report.resourceCatalogFailure == nil)
  }

  @Test(
    arguments: [
      ProductM2AuthorizedResourceSelectionError.leaseClosed,
      ProductM2AuthorizedResourceSelectionError.selectionAlreadyIssued,
      ProductM2AuthorizedResourceSelectionError.startAlreadyIssued,
      ProductM2AuthorizedResourceSelectionError.invalidSelection,
    ]
  )
  func everyClosedOrReplayMisuseHasSelectionReplayClass(
    _ error: ProductM2AuthorizedResourceSelectionError
  ) {
    var execution = ProductM2Execution(
      request: request(),
      networkWindow: NetworkCleanupCaptureWindow(),
      authorizationSource: .nativePortal
    )

    execution.applySelectionFailure(error)
    let report = execution.report()

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .selectionReplay)
    #expect(report.resourceCatalogFailure == nil)
  }

  @Test func preparedSelectionMismatchIsReportedExactly() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: snapshot,
        trace: trace,
        authorizationPrepare: { handle, target in
          let prepared = try ProductM2PortalAdapter.prepare(
            snapshot: snapshot,
            handle: handle,
            requiredTargetIPv4: target
          )
          return ProductM2PreparedAuthorizedResource(
            summary: ProductResourceSummary(
              handle: "different-generation:0",
              displayName: prepared.summary.displayName
            ),
            selectedRoutes: prepared.selectedRoutes,
            requiredTargetIPv4: target,
            withStartSnapshot: { _ in }
          )
        }
      )
    ).run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .preparedSelectionMismatch)
    #expect(report.resourceCatalogFailure == nil)
  }

  @Test func nonCatalogReportOmitsBothOptionalKeys() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Other NC"]))
    defer { fixture.erase() }

    let report = await catalogReport(snapshot: fixture.snapshot)
    let encoded = try #require(
      String(data: JSONEncoder().encode(report), encoding: .utf8))

    #expect(report.outcome == .resourceNotFound)
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.selectionFailureClass == nil)
    #expect(!encoded.contains("resourceCatalogFailure"))
    #expect(!encoded.contains("selectionFailureClass"))
  }

  private func catalogReport(
    snapshot: AuthenticatedPortalSnapshot
  ) async -> ProductM2ConnectReport {
    let trace = ProductM2TestTrace()
    return await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: snapshot, trace: trace)
    ).run(request())
  }

  private func report(
    using lease: ProductM2AuthorizedResourceLease
  ) async throws -> ProductM2ConnectReport {
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer { support.erase() }
    let trace = ProductM2TestTrace()
    return await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: support.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in
          ProductM2AuthorizationAttempt(
            source: .nativePortal,
            operation: {
              .acquired(
                source: .nativePortal,
                lease: lease,
                serverContactRequested: true
              )
            },
            cancel: {}
          )
        }
      )
    ).run(request())
  }

  private func classifiedLease(
    snapshot: AuthenticatedPortalSnapshot,
    catalog: @escaping ProductM2AuthorizedResourceLease.Catalog,
    prepare: @escaping ProductM2AuthorizedResourceLease.Prepare
  ) -> ProductM2AuthorizedResourceLease {
    ProductM2AuthorizedResourceLease(
      source: .nativePortal,
      catalog: catalog,
      prepare: prepare,
      eraseOwnedMaterial: {
        snapshot.erase()
        return snapshot.isErased
      },
      close: { _ in
        ProductM2AuthorizationCloseReceipt(
          outcome: .accepted,
          ownedMaterialErased: snapshot.isErased,
          sourceCloseRequested: true,
          serverContactRequested: false
        )
      }
    )
  }

  private func request() -> ProductM2ConnectRequest {
    ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
  }

  private func assertValueFree(
    _ report: ProductM2ConnectReport,
    sentinels: [String]
  ) throws {
    let encoded = try #require(
      String(data: JSONEncoder().encode(report), encoding: .utf8))
    let described = String(describing: report)
    for sentinel in sentinels {
      #expect(!encoded.contains(sentinel))
      #expect(!described.contains(sentinel))
    }
  }
}
