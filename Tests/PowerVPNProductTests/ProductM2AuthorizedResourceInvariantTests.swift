import PowerVPNCore
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AuthorizedResourceInvariantTests {

  @Test func preparedSummaryMustMatchTheCatalogCandidate() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let lease = ProductM2AuthorizedResourceLease(
      source: .nativePortal,
      catalog: { try ProductM2PortalAdapter.catalog(snapshot: snapshot) },
      prepare: { handle, target in
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
      },
      eraseOwnedMaterial: {
        snapshot.erase()
        return snapshot.isErased
      },
      close: { _ in
        ProductM2AuthorizationCloseReceipt(
          outcome: .accepted,
          ownedMaterialErased: snapshot.isErased,
          sourceCloseRequested: false,
          serverContactRequested: false
        )
      }
    )

    do {
      _ = try await lease.selectUnique(
        displayName: "Campus NC",
        requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
      )
      Issue.record("mismatched prepared summary was accepted")
    } catch let error as ProductM2AuthorizedResourceSelectionError {
      #expect(error == .preparedSelectionMismatch)
    }
    #expect(
      (await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)).outcome
        == .accepted)
  }

  @Test func duplicateCatalogHandlesAreRejectedBeforePrepare() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let candidate = try #require(
      ProductM2PortalAdapter.catalog(snapshot: snapshot).first
    )
    let trace = ProductM2TestTrace()
    let lease = ProductM2AuthorizedResourceLease(
      source: .nativePortal,
      catalog: { [candidate, candidate] },
      prepare: { _, _ in
        trace.record("prepare")
        throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
      },
      eraseOwnedMaterial: {
        snapshot.erase()
        return snapshot.isErased
      },
      close: { _ in acceptedCloseReceipt(snapshot: snapshot) }
    )

    let error = await invariantSelectionError {
      _ = try await lease.selectUnique(
        displayName: "Campus NC",
        requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
      )
    }

    #expect(error == .catalogInvariantInvalid)
    #expect(trace.count("prepare") == 0)
    #expect(
      (await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)).outcome
        == .accepted)
  }

  @Test func preparedTargetMismatchFailsBeforeBorrowOrControl() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let trace = ProductM2TestTrace()
    let requestedTarget = ProductM2SSHTarget.thu21.requiredTargetIPv4
    let otherTarget = ProductM2SSHTarget.thu52.requiredTargetIPv4
    let lease = ProductM2AuthorizedResourceLease(
      source: .nativePortal,
      catalog: { try ProductM2PortalAdapter.catalog(snapshot: snapshot) },
      prepare: { handle, target in
        let prepared = try ProductM2PortalAdapter.prepare(
          snapshot: snapshot,
          handle: handle,
          requiredTargetIPv4: target
        )
        return ProductM2PreparedAuthorizedResource(
          summary: prepared.summary,
          selectedRoutes: prepared.selectedRoutes,
          requiredTargetIPv4: otherTarget,
          withStartSnapshot: { _ in trace.record("start_snapshot_borrow") }
        )
      },
      eraseOwnedMaterial: {
        snapshot.erase()
        return snapshot.isErased
      },
      close: { _ in acceptedCloseReceipt(snapshot: snapshot) }
    )

    let error = await invariantSelectionError {
      _ = try await lease.selectUnique(
        displayName: "Campus NC",
        requiredTargetIPv4: requestedTarget
      )
    }

    #expect(error == .preparedSelectionMismatch)
    #expect(trace.count("start_snapshot_borrow") == 0)
    #expect(trace.count("begin_start") == 0)
    #expect(
      (await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)).outcome
        == .accepted)
  }

  @Test func crossResourceMatcherAndStartSnapshotFailBeforeControl() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: m2ResourceXML(["Campus A", "Campus B"])
    )
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let catalog = try ProductM2PortalAdapter.catalog(snapshot: snapshot)
    let resourceB = try #require(
      catalog.first { $0.summary.displayName == "Campus B" }
    )
    let trace = ProductM2TestTrace()
    let target = ProductM2SSHTarget.thu21.requiredTargetIPv4
    let lease = ProductM2AuthorizedResourceLease(
      source: .nativePortal,
      catalog: { catalog },
      prepare: { handle, requestedTarget in
        let resourceA = try ProductM2PortalAdapter.prepare(
          snapshot: snapshot,
          handle: handle,
          requiredTargetIPv4: requestedTarget
        )
        let independentLineage = VendorCharonStartLineage()
        return ProductM2PreparedAuthorizedResource(
          summary: resourceA.summary,
          selectedRoutes: resourceA.selectedRoutes,
          requiredTargetIPv4: requestedTarget,
          withStartSnapshot: { body in
            try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
              snapshot,
              handle: resourceB.summary.handle,
              lineage: independentLineage
            ) { startSnapshot in
              try body(startSnapshot)
            }
          }
        )
      },
      eraseOwnedMaterial: {
        snapshot.erase()
        return snapshot.isErased
      },
      close: { _ in acceptedCloseReceipt(snapshot: snapshot) }
    )
    let selection = try await lease.selectUnique(
      displayName: "Campus A",
      requiredTargetIPv4: target
    )

    let error = await invariantSelectionError {
      _ = try await selection.beginStart(
        control: productM2TestControl(trace: trace, plan: .acknowledged),
        deadline: m2TestBudget().work,
        peerGenerationValidator: { true }
      )
    }

    #expect(error == .startSnapshotRejected)
    #expect(trace.count("begin_start") == 0)
    #expect(
      (await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)).outcome
        == .accepted)
  }
}

private func acceptedCloseReceipt(
  snapshot: AuthenticatedPortalSnapshot
) -> ProductM2AuthorizationCloseReceipt {
  ProductM2AuthorizationCloseReceipt(
    outcome: .accepted,
    ownedMaterialErased: snapshot.isErased,
    sourceCloseRequested: false,
    serverContactRequested: false
  )
}

private func invariantSelectionError(
  _ operation: () async throws -> Void
) async -> ProductM2AuthorizedResourceSelectionError? {
  do {
    try await operation()
    return nil
  } catch let error as ProductM2AuthorizedResourceSelectionError {
    return error
  } catch {
    return nil
  }
}
