import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AuthorizedResourceSubmissionTests {
  @Test(arguments: [PostSubmissionWrapperBehavior.invokeTwice, .throwAfterInvocation])
  func coordinatorRetainsMutationReceiptAndRunsCleanup(
    behavior: PostSubmissionWrapperBehavior
  ) async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
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
            behavior: behavior
          )
        }
      )
    ).run(ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21))

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.cleanupVerified)
    #expect(trace.count("begin_start") == 1)
    #expect(trace.count("stop") == 1)
    #expect(snapshot.isErased)
  }

  @Test(arguments: [PostSubmissionWrapperBehavior.invokeTwice, .throwAfterInvocation])
  func postSubmissionWrapperBehaviorCannotErasePendingStart(
    behavior: PostSubmissionWrapperBehavior
  ) async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let trace = ProductM2TestTrace()
    let lease = ProductM2AuthorizedResourceLease(
      source: .vendorOnce,
      catalog: { try ProductM2PortalAdapter.catalog(snapshot: snapshot) },
      prepare: { handle, target in
        try wrappedPreparedResource(
          snapshot: snapshot,
          handle: handle,
          target: target,
          behavior: behavior
        )
      },
      eraseOwnedMaterial: {
        snapshot.erase()
        return snapshot.isErased
      },
      close: {
        ProductM2AuthorizationCloseReceipt(
          outcome: .accepted,
          ownedMaterialErased: snapshot.isErased,
          sourceCloseRequested: false,
          serverContactRequested: false
        )
      }
    )
    let selection = try await lease.selectUnique(
      displayName: "Campus NC",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )

    let pending = try await selection.beginStart(
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      peerGenerationValidator: { true }
    )
    let result = await pending.result()

    #expect(result.receipt.requestSent)
    #expect(result.receipt.transportAcknowledged)
    #expect(trace.count("begin_start") == 1)
    let stop = await result.lease?.stop()
    #expect(stop?.requestSent == true)
    #expect(trace.count("stop") == 1)
    #expect((await lease.closeAndErase()).outcome == .accepted)
  }
}

enum PostSubmissionWrapperBehavior: Sendable {
  case invokeTwice
  case throwAfterInvocation
}

private enum PostSubmissionWrapperError: Error {
  case afterInvocation
}

private func wrappedPreparedResource(
  snapshot: AuthenticatedPortalSnapshot,
  handle: String,
  target: UInt32,
  behavior: PostSubmissionWrapperBehavior
) throws -> ProductM2PreparedAuthorizedResource {
  let candidate = try #require(
    ProductM2PortalAdapter.catalog(snapshot: snapshot).first {
      $0.summary.handle == handle
    }
  )
  let lineage = VendorCharonStartLineage()
  var selectedRoutes: VendorCharonSelectedRouteMatcher?
  try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
    snapshot,
    handle: handle,
    lineage: lineage
  ) { startSnapshot in
    selectedRoutes = try startSnapshot.makeSelectedRouteMatcher(
      requiredTargetIPv4: target
    )
  }
  let matcher = try #require(selectedRoutes)
  return ProductM2PreparedAuthorizedResource(
    summary: candidate.summary,
    selectedRoutes: matcher,
    requiredTargetIPv4: target,
    withStartSnapshot: { body in
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        snapshot,
        handle: handle,
        lineage: lineage
      ) { startSnapshot in
        try body(startSnapshot)
        switch behavior {
        case .invokeTwice:
          try body(startSnapshot)
        case .throwAfterInvocation:
          throw PostSubmissionWrapperError.afterInvocation
        }
      }
    }
  )
}
