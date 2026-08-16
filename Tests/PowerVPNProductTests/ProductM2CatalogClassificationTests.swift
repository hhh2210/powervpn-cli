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

    let trace = ProductM2TestTrace()
    let report = try await report(using: lease, trace: trace)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .selectionReplay)
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.automaticRetryCount == 0)
    #expect(trace.count("acquire") == 1)

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

  @Test func catalogFailureRetriesWithFreshSessionThenSucceeds() async throws {
    let first = try authenticatedSnapshot(resourceXML: m2ResourceXML([]))
    let second = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer {
      first.erase()
      second.erase()
      support.erase()
    }
    let trace = ProductM2TestTrace()
    let firstState = AuthorizationLeaseTestState()
    let secondState = AuthorizationLeaseTestState()
    let firstLease = testAuthorizationLease(
      snapshot: first.snapshot,
      state: firstState,
      onClose: { trace.record("logout_1") }
    )
    let secondLease = testAuthorizationLease(
      snapshot: second.snapshot,
      state: secondState,
      onClose: { trace.record("logout_2") }
    )
    let attempts = ProductM2AuthorizationAttemptQueue([
      authorizationAttempt(firstLease, trace: trace, label: "login_1"),
      authorizationAttempt(secondLease, trace: trace, label: "login_2"),
    ])
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: support.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in attempts.next() }
      )
    ).run(request())

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.automaticRetryCount == 1)
    #expect(firstState.closeCount == 1)
    #expect(secondState.closeCount == 1)
    #expect(
      trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
        == ["login_1", "logout_1", "login_2", "logout_2"]
    )
    let object = try #require(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
    #expect(object["automaticRetryCount"] as? Int == 1)
  }

  @Test func secondCatalogFailureWinsAndNeverRetriesAgain() async throws {
    let first = try authenticatedSnapshot(resourceXML: m2ResourceXML([]))
    let sentinel = "second-attempt-invalid"
    let second = try authenticatedSnapshot(
      resourceXML: m2ResourceXML(["Campus NC"])
        .replacingOccurrences(of: "port=\"500\"", with: "port=\"\(sentinel)\"")
    )
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer {
      first.erase()
      second.erase()
      support.erase()
    }
    let trace = ProductM2TestTrace()
    let firstState = AuthorizationLeaseTestState()
    let secondState = AuthorizationLeaseTestState()
    let attempts = ProductM2AuthorizationAttemptQueue([
      authorizationAttempt(
        testAuthorizationLease(
          snapshot: first.snapshot,
          state: firstState,
          onClose: { trace.record("logout_1") }
        ),
        trace: trace,
        label: "login_1"
      ),
      authorizationAttempt(
        testAuthorizationLease(
          snapshot: second.snapshot,
          state: secondState,
          onClose: { trace.record("logout_2") }
        ),
        trace: trace,
        label: "login_2"
      ),
    ])

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: support.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in attempts.next() }
      )
    ).run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.automaticRetryCount == 1)
    #expect(report.selectionFailureClass == .catalogMapping)
    #expect(report.resourceCatalogFailure?.failureClass == .integerInvalid)
    #expect(report.resourceCatalogFailure?.fieldPath == "common.ike_port")
    #expect(firstState.closeCount == 1)
    #expect(secondState.closeCount == 1)
    #expect(
      trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
        == ["login_1", "logout_1", "login_2", "logout_2"]
    )
    try assertValueFree(report, sentinels: [sentinel])
  }

  @Test func retryLoginFailureKeepsFirstLogoutAndReportsSecondFailure() async throws {
    let first = try authenticatedSnapshot(resourceXML: m2ResourceXML([]))
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer {
      first.erase()
      support.erase()
    }
    let trace = ProductM2TestTrace()
    let state = AuthorizationLeaseTestState()
    let firstLease = testAuthorizationLease(
      snapshot: first.snapshot,
      state: state,
      onClose: { trace.record("logout_1") }
    )
    let attempts = ProductM2AuthorizationAttemptQueue([
      authorizationAttempt(firstLease, trace: trace, label: "login_1"),
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
    ).run(request())

    #expect(report.outcome == .authorizationAcquisitionRejected)
    #expect(report.authorizationFailure == .providerUnavailable)
    #expect(report.authorizationAcquisition == .rejected)
    #expect(report.automaticRetryCount == 1)
    #expect(report.cleanupVerified)
    #expect(state.closeCount == 1)
    #expect(
      trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
        == ["login_1", "logout_1", "login_2"]
    )
  }

  @Test func insufficientAcquisitionBudgetSkipsCatalogRetry() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML([]))
    let snapshot = fixture.snapshot
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer { fixture.erase() }
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
    ).run(request(), budget: budget)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.automaticRetryCount == 0)
    #expect(state.closeCount == 1)
    #expect(trace.events.filter { $0.hasPrefix("login_") } == ["login_1"])
  }

  @Test func nonCatalogReportOmitsBothOptionalKeys() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Other NC"]))
    defer { fixture.erase() }

    let trace = ProductM2TestTrace()
    let report = await catalogReport(snapshot: fixture.snapshot, trace: trace)
    let encoded = try #require(
      String(data: JSONEncoder().encode(report), encoding: .utf8))

    #expect(report.outcome == .resourceNotFound)
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.selectionFailureClass == nil)
    #expect(report.automaticRetryCount == 0)
    #expect(trace.count("acquire") == 1)
    #expect(!encoded.contains("resourceCatalogFailure"))
    #expect(!encoded.contains("selectionFailureClass"))
  }

  private func catalogReport(
    snapshot: AuthenticatedPortalSnapshot,
    trace: ProductM2TestTrace = ProductM2TestTrace()
  ) async -> ProductM2ConnectReport {
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    clock.set(milliseconds: 36_000)
    return await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(snapshot: snapshot, trace: trace)
    ).run(request(), budget: budget)
  }

  private func report(
    using lease: ProductM2AuthorizedResourceLease,
    trace: ProductM2TestTrace = ProductM2TestTrace()
  ) async throws -> ProductM2ConnectReport {
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
    defer { support.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    clock.set(milliseconds: 36_000)
    return await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: support.snapshot,
        trace: trace,
        beginAuthorizationOverride: { _ in
          ProductM2AuthorizationAttempt(
            source: .nativePortal,
            operation: {
              trace.record("acquire")
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
    ).run(request(), budget: budget)
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

  private func authorizationAttempt(
    _ lease: ProductM2AuthorizedResourceLease,
    trace: ProductM2TestTrace,
    label: String
  ) -> ProductM2AuthorizationAttempt {
    ProductM2AuthorizationAttempt(
      source: .nativePortal,
      operation: {
        trace.record(label)
        return .acquired(
          source: .nativePortal,
          lease: lease,
          serverContactRequested: true
        )
      },
      cancel: {}
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
