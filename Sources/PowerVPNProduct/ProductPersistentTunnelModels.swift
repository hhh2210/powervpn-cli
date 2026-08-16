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
  package var firstBadEvent: ProductM2BadEvent? = nil
  package let state: ProductPersistentTunnelState
  package let helperMutationRequested: Bool
  package let serverContactRequested: Bool
  package let authorizationClose: ProductM2AuthorizationCloseOutcome
  package let authorizationOwnedMaterialErased: Bool
  package let cleanupVerified: Bool
  /// Cleanup restoration booleans are measured only when this state is
  /// `measured_complete`; other false values are fail-closed placeholders.
  package var cleanupCaptureState: ProductM2CleanupCaptureState? = nil
  package var cleanupCaptureRetryReason: ProductM2CleanupCaptureRetryReason? = nil
  package var cleanupCaptureAttemptCount = 0
  package let containsSecrets = false
  /// Schema-10 diagnostic classification mirrored from the underlying M2
  /// connect report; nil — omitted from JSON — when not applicable.
  package var activeCaptureState: ProductM2ActiveCaptureState? = nil
  package var activeCaptureChangeAxes: [ProductM2ActiveCaptureChangeAxis]? = nil
  package var activeCaptureIncompleteReason: ProductM2ActiveCaptureIncompleteReason? = nil
  package var stopInvalidityClass: ProductM2StopInvalidityClass? = nil
  /// Schema-11 network-proof source mirrored from the underlying M2
  /// execution; nil — omitted from JSON — when not applicable.
  package var networkProofSource: ProductM2NetworkProofSource? = nil

  private enum CodingKeys: String, CodingKey {
    case outcome
    case failure
    case state
    case helperMutationRequested
    case serverContactRequested
    case authorizationClose
    case authorizationOwnedMaterialErased
    case cleanupVerified
    case cleanupCaptureState
    case cleanupCaptureRetryReason
    case cleanupCaptureAttemptCount
    case containsSecrets
    case activeCaptureState
    case activeCaptureChangeAxes
    case activeCaptureIncompleteReason
    case stopInvalidityClass
    case networkProofSource
  }

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
  /// Cleanup restoration booleans are measured only when this state is
  /// `measured_complete`; other false values are fail-closed placeholders.
  package var cleanupCaptureState: ProductM2CleanupCaptureState? = nil
  package var cleanupCaptureRetryReason: ProductM2CleanupCaptureRetryReason? = nil
  package var cleanupCaptureAttemptCount = 0
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
