import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Deterministic offline replay of the intermittent portal catalog
/// rejection (recorded live 2026-08-12 / 2026-08-15 / 2026-08-16; rank-1
/// hypothesis: fresh-login-per-run session lifecycle vs the official
/// client's one-login-per-app-lifetime profile, see the catalog
/// investigation dossiers). CI never contacts the real portal; this suite
/// replays every recorded rejection shape through the real acquisition
/// pipeline — snapshot minting, `selectUnique`, typed classification,
/// exactly-one fresh-login retry — and asserts the retry state machine:
///
/// - catalog classes retry exactly once, first session logged out before
///   the re-login, and `automaticRetryCount` stays truthful;
/// - non-catalog classes never retry;
/// - an exhausted retry reports the complete discriminator pair
///   (`selectionFailureClass` + `resourceCatalogFailure`) value-free;
/// - budget exhaustion skips the retry;
/// - classification is invariant to shape serving order (no static or
///   session state leaks between acquisitions within one process).
///
/// Placement note: this suite lives in `PowerVPNProductTests` (selected by
/// `swift test --filter CatalogReplay`) because the entire injection seam
/// layer — `productM2TestDependencies`, `authenticatedSnapshot`,
/// `testAuthorizationLease`, `ProductM2AuthorizationAttemptQueue` — is
/// target-local, and SwiftPM forbids test targets depending on test
/// targets; a separate target would duplicate that harness.
@Suite struct CatalogReplayTests {

  // MARK: exactly-one retry with a fresh session, then success

  @Test(
    arguments: CatalogReplayMatrix.shapes
  )
  func catalogReplayRetriesOnceWithFreshSessionThenSucceeds(
    _ shape: CatalogReplayShape
  ) async throws {
    let report = try await replay(shape: shape, secondCatalog: .healthy)

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.automaticRetryCount == 1)
    #expect(report.selectionFailureClass == nil)
    #expect(report.resourceCatalogFailure == nil)
    try assertValueFree(report, shape: shape)
  }

  // MARK: exhaustion after exactly one retry, truthful discriminators

  @Test(
    arguments: CatalogReplayMatrix.shapes
  )
  func catalogReplayExhaustsAfterExactlyOneRetryWithTruthfulTokens(
    _ shape: CatalogReplayShape
  ) async throws {
    let report = try await replay(shape: shape, secondCatalog: .rejected)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.firstBadEvent == .resourceCatalogRejected)
    #expect(report.automaticRetryCount == 1)
    #expect(report.selectionFailureClass == shape.expectedClass)
    #expect(report.resourceCatalogFailure == shape.expectedFailure)
    try assertValueFree(report, shape: shape)

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

  // MARK: non-catalog classes never retry

  @Test func resourceNotFoundNeverRetries() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML(["other-resource"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let trace = ProductM2TestTrace()
    let state = AuthorizationLeaseTestState()

    let report = try await singleAttemptRun(
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

    let report = try await singleAttemptRun(lease: lease, trace: trace)

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
    ).run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.selectionFailureClass == .prepareRemap)
    #expect(report.resourceCatalogFailure?.failureClass == .snapshotInaccessible)
    #expect(report.automaticRetryCount == 0)
    #expect(trace.count("acquire") == 1)
  }

  // MARK: budget gate

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
    ).run(request(), budget: budget)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.automaticRetryCount == 0)
    #expect(report.selectionFailureClass == shape.expectedClass)
    #expect(report.resourceCatalogFailure == shape.expectedFailure)
    #expect(trace.events.filter { $0.hasPrefix("login_") } == ["login_1"])
    #expect(state.closeCount == 1)
  }

  // MARK: retry whose fresh login is rejected

  @Test func rejectedFreshLoginKeepsFirstLogoutAndReportsTheRejection() async throws {
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
    ).run(request())

    #expect(report.outcome == .authorizationAcquisitionRejected)
    #expect(report.authorizationFailure == .providerUnavailable)
    #expect(report.automaticRetryCount == 1)
    #expect(report.cleanupVerified)
    #expect(state.closeCount == 1)
    #expect(
      trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
        == ["login_1", "logout_1", "login_2"])
  }

  // MARK: order-dependence

  /// Shape serving order must not change any classification: the state
  /// machine must hold no static or cross-acquisition state. Seeds come
  /// from `CATALOG_REPLAY_PERMUTATIONS` (deterministic rotations; nightly
  /// CI passes one seed per matrix leg).
  @Test func classificationIsInvariantToShapeServingOrder() async throws {
    let seeds = CatalogReplayMatrix.permutationSeeds()
    #expect(!seeds.isEmpty)

    for seed in seeds {
      for shape in CatalogReplayMatrix.order(seed: seed) {
        let fixture = try authenticatedSnapshot(resourceXML: shape.resourceXML)
        defer { fixture.erase() }
        let clock = ProductM2ManualClock()
        let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
        clock.set(milliseconds: 36_000)
        let trace = ProductM2TestTrace()

        let report = await ProductM2ConnectOnceCoordinator(
          dependencies: productM2TestDependencies(
            snapshot: fixture.snapshot, trace: trace
          )
        ).run(request(), budget: budget)

        #expect(
          report.selectionFailureClass == shape.expectedClass,
          "seed \(seed) shape \(shape.label)")
        #expect(
          report.resourceCatalogFailure == shape.expectedFailure,
          "seed \(seed) shape \(shape.label)")
        #expect(report.automaticRetryCount == 0)
      }
    }
  }

  // MARK: taxonomy coverage pins

  /// The replay matrix must keep covering the full server-reachable
  /// taxonomy. Classes absent here are pinned to their existing coverage:
  /// `resource_list_duplicate` is rejected by the snapshot-descriptor gate
  /// at mint time (acquisition stage, before any lease exists — asserted
  /// below), `material_too_large` by the bounded parser before mapping,
  /// `snapshot_inaccessible` is a client-lifecycle class, and
  /// `unclassified` is the defensive total.
  @Test func replayMatrixCoversTheServerReachableTaxonomy() {
    let covered = Set(
      CatalogReplayMatrix.shapes.compactMap { $0.expectedFailure?.failureClass })
    let expected: Set<ProductResourceCatalogFailureClass> = [
      .integrationInfoMissing, .resourceListMissing,
      .majorVersionMissing, .majorVersionDuplicate, .majorVersionMalformed,
      .majorVersionInvalid,
      .integerInvalid, .displayNameMissing, .displayNameInvalid, .duplicateField,
    ]
    #expect(covered == expected)
  }

  @Test func duplicateResourceListIsRejectedAtMintBeforeAnyLease() {
    var minted = false
    do {
      _ = try authenticatedSnapshot(
        resourceXML: "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/>"
          + "<RESOURCE_LIST/><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>")
      minted = true
    } catch {}
    #expect(!minted, "duplicate RESOURCE_LIST must be rejected by the mint gate")
  }

  // MARK: harness

  private enum SecondCatalog {
    case healthy
    case rejected
  }

  private func replay(
    shape: CatalogReplayShape,
    secondCatalog: SecondCatalog
  ) async throws -> ProductM2ConnectReport {
    let first = try authenticatedSnapshot(resourceXML: shape.resourceXML)
    let secondXML: String
    switch secondCatalog {
    case .healthy:
      secondXML = m2ResourceXML([CatalogReplayMatrix.requestedDisplayName])
    case .rejected:
      secondXML = shape.resourceXML
    }
    let second = try authenticatedSnapshot(resourceXML: secondXML)
    let support = try authenticatedSnapshot(resourceXML: m2ResourceXML(["support-only"]))
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
    ).run(request())

    #expect(
      trace.events.filter { $0.hasPrefix("login_") || $0.hasPrefix("logout_") }
        == ["login_1", "logout_1", "login_2", "logout_2"])
    return report
  }

  private func singleAttemptRun(
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
    ).run(request())
  }

  private func assertValueFree(
    _ report: ProductM2ConnectReport,
    shape: CatalogReplayShape
  ) throws {
    let encoded = try #require(
      String(data: JSONEncoder().encode(report), encoding: .utf8))
    let described = String(describing: report)
    for sentinel in CatalogReplayMatrix.universalSentinels + shape.sentinels {
      #expect(!encoded.contains(sentinel))
      #expect(!described.contains(sentinel))
    }
  }

  private func request() -> ProductM2ConnectRequest {
    ProductM2ConnectRequest(
      resourceDisplayName: CatalogReplayMatrix.requestedDisplayName,
      sshTarget: .thu21
    )
  }
}
