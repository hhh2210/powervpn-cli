import PowerVPNCore

package enum ProductPersistentTunnelState: String, Encodable, Equatable, Sendable {
  case idle
  case starting
  case active
  case stopping
  case stopped
}

package enum ProductPersistentTunnelOpenOutcome: String, Encodable, Equatable, Sendable {
  case opened
  case rejected
}

package struct ProductPersistentTunnelOpenReport: Encodable, Equatable, Sendable {
  package let outcome: ProductPersistentTunnelOpenOutcome
  package let failure: ProductM2ConnectOutcome?
  package let state: ProductPersistentTunnelState
  package let helperMutationRequested: Bool
  package let serverContactRequested: Bool
  package let authorizationClose: ProductM2AuthorizationCloseOutcome
  package let authorizationOwnedMaterialErased: Bool
  package let cleanupVerified: Bool
  package let containsSecrets = false

  package var opened: Bool {
    outcome == .opened && state == .active
  }
}

package enum ProductPersistentTunnelOpenResult: Sendable {
  case opened(ProductPersistentTunnelLease, ProductPersistentTunnelOpenReport)
  case failed(ProductPersistentTunnelOpenReport)

  package var report: ProductPersistentTunnelOpenReport {
    switch self {
    case .opened(_, let report), .failed(let report): report
    }
  }
}

package struct ProductPersistentTunnelShutdownReport: Encodable, Equatable, Sendable {
  package let state: ProductPersistentTunnelState
  package let cleanupPath: ProductM2CleanupPath
  package let stopOutcome: ProductM2ControlOutcome
  package let emergencyStopOutcome: ProductM2ControlOutcome
  package let authorizationClose: ProductM2AuthorizationCloseOutcome
  package let authorizationOwnedMaterialErased: Bool
  package let cleanupVerified: Bool
  package let containsSecrets = false

  package var disconnected: Bool {
    state == .stopped && cleanupVerified
  }
}

struct ProductPersistentTunnelSessionAssets: Sendable {
  var execution: ProductM2Execution
  let baseline: ProductM2NetworkBaseline
  let coldGeneration: VendorHelperGenerationSnapshot
  let selectedRoutes: VendorCharonSelectedRouteMatcher
  let controlAuthority: ProductM2ControlCleanupAuthority
  let authorizationLease: ProductM2AuthorizedResourceLease
  let mutationLease: any ProductMutationLeaseHolding
}

enum ProductPersistentTunnelSessionOpenResult: Sendable {
  case active(ProductPersistentTunnelSessionAssets)
  case failed(ProductM2ConnectReport)
}
