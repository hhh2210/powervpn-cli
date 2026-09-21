import PowerVPNCore

package struct ProductCleanupRecoveryRequest: Equatable, Sendable {
  package let resourceDisplayName: String
  package let sshTarget: ProductM2SSHTarget

  package init(resourceDisplayName: String, sshTarget: ProductM2SSHTarget) {
    self.resourceDisplayName = resourceDisplayName
    self.sshTarget = sshTarget
  }
}

package enum ProductCleanupRecoveryBasis: String, Encodable, Equatable, Sendable {
  case currentProfileColdBaseline = "current_profile_cold_baseline"
}

package enum ProductCleanupRecoveryOutcome: String, Encodable, Equatable, Sendable {
  case recovered
  case rejected
}

package enum ProductCleanupRecoveryFailure: String, Encodable, Equatable, Sendable {
  case mutationLeaseUnavailable = "mutation_lease_unavailable"
  case authorizationUnavailable = "authorization_unavailable"
  case authorizationRejected = "authorization_rejected"
  case selectionRejected = "selection_rejected"
  case authorizationCloseRejected = "authorization_close_rejected"
  case captureUnavailable = "capture_unavailable"
  case preflightRejected = "preflight_rejected"
  case coldBaselineRejected = "cold_baseline_rejected"
  case receiptPersistenceRejected = "receipt_persistence_rejected"
  case cancelled
}

package struct ProductCleanupRecoveryReport: Encodable, Equatable, Sendable {
  package let schemaVersion = 1
  package let outcome: ProductCleanupRecoveryOutcome
  package let basis = ProductCleanupRecoveryBasis.currentProfileColdBaseline
  package let failure: ProductCleanupRecoveryFailure?
  package let authorizationSource: ProductM2AuthorizationSource
  package let authorizationFailure: ProductM2AuthorizationFailure?
  package let authorizationClose: ProductM2AuthorizationCloseOutcome
  package let authorizationOwnedMaterialErased: Bool
  package let serverContactRequested: Bool
  package let captureAssessment: NetworkColdRecoveryAssessment?
  package let captureAttemptCount: Int
  package let preflightSafe: Bool
  package let mutationLeaseAcquired: Bool
  package let originalCleanupRestored = false
  package let permitsReconnect: Bool
  package let containsSecrets = false

  init(
    failure: ProductCleanupRecoveryFailure?,
    source: ProductM2AuthorizationSource,
    authorizationFailure: ProductM2AuthorizationFailure? = nil,
    close: ProductM2AuthorizationCloseReceipt? = nil,
    contacted: Bool = false,
    assessment: NetworkColdRecoveryAssessment? = nil,
    attempts: Int = 0,
    preflightSafe: Bool = false,
    mutationLeaseAcquired: Bool
  ) {
    precondition((0...2).contains(attempts))
    authorizationSource = source
    self.authorizationFailure = authorizationFailure
    authorizationClose = close?.outcome ?? .notRequired
    authorizationOwnedMaterialErased = close?.ownedMaterialErased ?? true
    serverContactRequested = contacted || (close?.serverContactRequested ?? false)
    captureAssessment = assessment
    captureAttemptCount = attempts
    self.preflightSafe = preflightSafe
    self.mutationLeaseAcquired = mutationLeaseAcquired
    let accepted =
      mutationLeaseAcquired && authorizationClose == .accepted
      && authorizationOwnedMaterialErased && attempts == 2 && assessment?.passed == true
      && preflightSafe && failure == nil
    outcome = accepted ? .recovered : .rejected
    self.failure = accepted ? nil : (failure ?? .coldBaselineRejected)
    permitsReconnect = accepted
  }

  init(persistenceRejected report: Self) {
    precondition(report.permitsReconnect)
    outcome = .rejected
    failure = .receiptPersistenceRejected
    authorizationSource = report.authorizationSource
    authorizationFailure = report.authorizationFailure
    authorizationClose = report.authorizationClose
    authorizationOwnedMaterialErased = report.authorizationOwnedMaterialErased
    serverContactRequested = report.serverContactRequested
    captureAssessment = report.captureAssessment
    captureAttemptCount = report.captureAttemptCount
    preflightSafe = report.preflightSafe
    mutationLeaseAcquired = report.mutationLeaseAcquired
    permitsReconnect = false
  }

  init(cancelled report: Self) {
    outcome = .rejected
    failure = .cancelled
    authorizationSource = report.authorizationSource
    authorizationFailure = report.authorizationFailure
    authorizationClose = report.authorizationClose
    authorizationOwnedMaterialErased = report.authorizationOwnedMaterialErased
    serverContactRequested = report.serverContactRequested
    captureAssessment = report.captureAssessment
    captureAttemptCount = report.captureAttemptCount
    preflightSafe = report.preflightSafe
    mutationLeaseAcquired = report.mutationLeaseAcquired
    permitsReconnect = false
  }
}

package struct ProductCleanupRecoveryDependencies: Sendable {
  package typealias Capture =
    @Sendable (
      NetworkCleanupCaptureWindow,
      VendorCharonSelectedRouteMatcher,
      ProductM2StageDeadline
    ) async -> NetworkCleanupSnapshot
  package typealias CheckPreflight =
    @Sendable (
      VendorHelperGenerationSnapshot,
      ProductM2StageDeadline
    ) async -> VendorXPCPreflightEvidence
  package typealias ObserveGeneration =
    @Sendable (ProductM2StageDeadline) async -> VendorHelperGenerationSnapshot

  package let acquireMutationLease: @Sendable () throws -> any ProductMutationLeaseHolding
  package let authorizationSource: ProductM2AuthorizationSource
  package let authorizationAvailabilityFailure: ProductM2AuthorizationFailure?
  package let beginAuthorization:
    @Sendable (ProductM2AuthorizationBudget) -> ProductM2AuthorizationAttempt
  package let observeGeneration: ObserveGeneration
  package let captureNetwork: Capture
  package let checkPreflight: CheckPreflight

  package init(
    acquireMutationLease: @escaping @Sendable () throws -> any ProductMutationLeaseHolding,
    authorizationSource: ProductM2AuthorizationSource = .nativePortal,
    authorizationAvailabilityFailure: ProductM2AuthorizationFailure? = nil,
    beginAuthorization:
      @escaping @Sendable (ProductM2AuthorizationBudget) -> ProductM2AuthorizationAttempt,
    observeGeneration: @escaping ObserveGeneration,
    captureNetwork: @escaping Capture,
    checkPreflight: @escaping CheckPreflight
  ) {
    self.acquireMutationLease = acquireMutationLease
    self.authorizationSource = authorizationSource
    self.authorizationAvailabilityFailure = authorizationAvailabilityFailure
    self.beginAuthorization = beginAuthorization
    self.observeGeneration = observeGeneration
    self.captureNetwork = captureNetwork
    self.checkPreflight = checkPreflight
  }
}
