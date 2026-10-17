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
  /// Package-only catalog diagnostics mirrored from the underlying M2 report.
  /// Deliberately excluded from `CodingKeys` to preserve the open-report schema.
  package var selectionFailureClass: ProductM2SelectionFailureClass? = nil
  package var resourceCatalogFailure: ProductResourceCatalogFailure? = nil
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
  /// Full value-free cleanup receipt for a failed open that reached cleanup.
  /// Excluded from `CodingKeys` to preserve the public open-report schema.
  package var cleanupReceipt: ProductPersistentTunnelShutdownReport? = nil

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
  /// Verdict-shaped path: `.cleanupUnproven` whenever verification failed,
  /// even if the control path itself was classified. Kept as is for the
  /// persisted schema; see `controlCleanupPath` for the path actually taken.
  package let cleanupPath: ProductM2CleanupPath
  /// The control cleanup path the runner actually took, never replaced by the
  /// verification verdict. Nil only when a report did not record it.
  package var controlCleanupPath: ProductM2CleanupPath? = nil
  package let stopOutcome: ProductM2ControlOutcome
  package let emergencyStopOutcome: ProductM2ControlOutcome
  package let authorizationClose: ProductM2AuthorizationCloseOutcome
  package let authorizationOwnedMaterialErased: Bool
  /// Closed, value-free restoration dimensions from the final bounded capture.
  package let cleanupEvidence: ProductM2CleanupEvidence
  package let cleanupVerified: Bool
  /// Cleanup restoration booleans are measured only when this state is
  /// `measured_complete`; other false values are fail-closed placeholders.
  package var cleanupCaptureState: ProductM2CleanupCaptureState? = nil
  package var cleanupCaptureRetryReason: ProductM2CleanupCaptureRetryReason? = nil
  package var cleanupCaptureAttemptCount = 0
  package let containsSecrets = false

  package init(
    state: ProductPersistentTunnelState,
    cleanupPath: ProductM2CleanupPath,
    controlCleanupPath: ProductM2CleanupPath? = nil,
    stopOutcome: ProductM2ControlOutcome,
    emergencyStopOutcome: ProductM2ControlOutcome,
    authorizationClose: ProductM2AuthorizationCloseOutcome,
    authorizationOwnedMaterialErased: Bool,
    cleanupEvidence: ProductM2CleanupEvidence = .unavailable,
    cleanupVerified: Bool,
    cleanupCaptureState: ProductM2CleanupCaptureState? = nil,
    cleanupCaptureRetryReason: ProductM2CleanupCaptureRetryReason? = nil,
    cleanupCaptureAttemptCount: Int = 0
  ) {
    self.state = state
    self.cleanupPath = cleanupPath
    self.controlCleanupPath = controlCleanupPath
    self.stopOutcome = stopOutcome
    self.emergencyStopOutcome = emergencyStopOutcome
    self.authorizationClose = authorizationClose
    self.authorizationOwnedMaterialErased = authorizationOwnedMaterialErased
    self.cleanupEvidence = cleanupEvidence
    self.cleanupVerified = cleanupVerified
    self.cleanupCaptureState = cleanupCaptureState
    self.cleanupCaptureRetryReason = cleanupCaptureRetryReason
    self.cleanupCaptureAttemptCount = cleanupCaptureAttemptCount
  }

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
