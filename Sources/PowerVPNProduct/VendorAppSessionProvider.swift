import PowerVPNCore

package struct VendorAppSessionProvider: ProductM2AuthorizedResourceProviding {
  package let source = ProductM2AuthorizationSource.vendorOnce
  private let state: VendorAppSessionProviderState

  package init() {
    state = VendorAppSessionProviderState()
  }

  init(state: VendorAppSessionProviderState) {
    self.state = state
  }

  package var availabilityFailure: ProductM2AuthorizationFailure? {
    state.isAvailable ? nil : .providerUnavailable
  }

  package func beginAcquire(
    budget: ProductM2AuthorizationBudget
  ) -> ProductM2AuthorizationAttempt {
    ProductM2AuthorizationAttempt(
      source: .vendorOnce,
      operation: {
        guard budget.work.hasRemaining else {
          return Self.rejected(.timedOut)
        }
        guard let material = self.state.claimForAcquisition() else {
          return Self.rejected(.providerUnavailable)
        }
        return .acquired(
          source: .vendorOnce,
          lease: Self.lease(material),
          serverContactRequested: false
        )
      },
      cancel: {}
    )
  }

  func readinessCandidate() -> ProductResourceCandidate? {
    state.readinessCandidate()
  }

  private static func lease(
    _ material: VendorAppSessionSnapshotMaterial
  ) -> ProductM2AuthorizedResourceLease {
    ProductM2AuthorizedResourceLease(
      source: .vendorOnce,
      catalog: {
        [ProductResourceCandidate(summary: material.summary, validation: material.validation)]
      },
      prepare: { handle, requiredTargetIPv4 in
        guard handle == material.summary.handle,
          let snapshot = material.validation.snapshot
        else { throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected }
        let matcher: VendorCharonSelectedRouteMatcher
        do {
          matcher = try snapshot.makeSelectedRouteMatcher(
            requiredTargetIPv4: requiredTargetIPv4
          )
        } catch VendorCharonSelectedRouteMatcherError.requiredTargetNotCovered {
          throw ProductM2AuthorizedResourceSelectionError.selectedRouteCoverageRejected
        } catch {
          throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
        }
        return ProductM2PreparedAuthorizedResource(
          summary: material.summary,
          selectedRoutes: matcher,
          requiredTargetIPv4: requiredTargetIPv4,
          withStartSnapshot: { body in
            guard material.sourceIsCurrent,
              let current = material.validation.snapshot
            else {
              throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
            }
            try body(current)
          }
        )
      },
      eraseOwnedMaterial: {
        material.erase()
        return material.isErased
      },
      close: { _ in
        material.erase()
        return ProductM2AuthorizationCloseReceipt(
          outcome: .accepted,
          ownedMaterialErased: material.isErased,
          sourceCloseRequested: false,
          serverContactRequested: false
        )
      }
    )
  }

  private static func rejected(
    _ failure: ProductM2AuthorizationFailure
  ) -> ProductM2AuthorizedResourceAcquisition {
    .rejected(
      source: .vendorOnce,
      failure: failure,
      cleanup: ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: true,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    )
  }
}
