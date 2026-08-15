import Foundation
import PowerVPNCore

public enum ProductM2ConnectionState: String, Encodable, Equatable, Sendable {
  case signedOut = "signed_out"
  case authenticating
  case ready
  case connecting
  case connected
  case disconnecting
  case disconnected
  case blocked
  case failed
}

public enum ProductM2SSHTarget: String, Encodable, Equatable, Sendable {
  case thu21
  case thu52
}

public enum ProductM2ConnectOutcome: String, Encodable, Equatable, Sendable {
  case connectedAndCleanedUp = "connected_and_cleaned_up"
  case preflightBlocked = "preflight_blocked"
  case networkBaselineUnavailable = "network_baseline_unavailable"
  case networkBaselineChanged = "network_baseline_changed"
  case authorizationAcquisitionRejected = "authorization_acquisition_rejected"
  case resourceCatalogRejected = "resource_catalog_rejected"
  case resourceNotFound = "resource_not_found"
  case resourceAmbiguous = "resource_ambiguous"
  case selectedRouteCoverageRejected = "selected_route_coverage_rejected"
  case generationFenceRejected = "generation_fence_rejected"
  case startSnapshotRejected = "start_snapshot_rejected"
  case startRejected = "start_rejected"
  case vendorStatusUnproven = "vendor_status_unproven"
  case activeNetworkUnproven = "active_network_unproven"
  case sshProofRejected = "ssh_proof_rejected"
  case deadlineExceeded = "deadline_exceeded"
  case cancelled
  case cleanupUnproven = "cleanup_unproven"
}

public enum ProductM2BadEvent: String, Encodable, Equatable, Sendable {
  case preflightRejected = "preflight_rejected"
  case networkBaselineUnavailable = "network_baseline_unavailable"
  case networkBaselineChanged = "network_baseline_changed"
  case authorizationAcquisitionRejected = "authorization_acquisition_rejected"
  case resourceCatalogRejected = "resource_catalog_rejected"
  case resourceNotFound = "resource_not_found"
  case resourceAmbiguous = "resource_ambiguous"
  case selectedRouteCoverageRejected = "selected_route_coverage_rejected"
  case generationFenceRejected = "generation_fence_rejected"
  case startSnapshotRejected = "start_snapshot_rejected"
  case startControlRejected = "start_control_rejected"
  case postStartGenerationRejected = "post_start_generation_rejected"
  case vendorStatusUnproven = "vendor_status_unproven"
  case activeNetworkUnproven = "active_network_unproven"
  case sshProofRejected = "ssh_proof_rejected"
  case deadlineExceeded = "deadline_exceeded"
  case cancelled
  case authorizationCloseRejected = "authorization_close_rejected"
  case cleanupVerificationRejected = "cleanup_verification_rejected"
}

public enum ProductM2ControlOutcome: String, Encodable, Equatable, Sendable {
  case notAttempted = "not_attempted"
  case transportAcknowledged = "transport_acknowledged"
  case preflightBlocked = "preflight_blocked"
  case helperVersionMismatch = "helper_version_mismatch"
  case helperVersionRejected = "helper_version_rejected"
  case invalidTimeout = "invalid_timeout"
  case cancelled
  case timeout
  case snapshotEncodingFailed = "snapshot_encoding_failed"
  case peerGenerationMismatch = "peer_generation_mismatch"
  case connectionInterrupted = "connection_interrupted"
  case connectionInvalid = "connection_invalid"
  case peerCodeSigningRequirement = "peer_code_signing_requirement"
  case unexpectedXPCError = "unexpected_xpc_error"
  case unexpectedConnectionEvent = "unexpected_connection_event"
  case unexpectedReplyPayload = "unexpected_reply_payload"
  case leaseClosed = "lease_closed"
}

public enum ProductM2AuthorizationAcquisitionOutcome: String, Encodable, Equatable, Sendable {
  case notRequested = "not_requested"
  case acquired
  case rejected
  case cancelled
}

public enum ProductM2AuthorizationCloseOutcome: String, Encodable, Equatable, Sendable {
  case notRequired = "not_required"
  case accepted
  case rejected
  case timedOut = "timed_out"
  case cancelled
  case alreadyClosed = "already_closed"
}

public enum ProductM2CleanupPath: String, CaseIterable, Encodable, Equatable, Sendable {
  case notRequired = "not_required"
  case sameLeaseStop = "same_lease_stop"
  case sameSessionProvisionalStop = "same_session_provisional_stop"
  case naturalHelperExit = "natural_helper_exit"
  case authenticatedEmergencyStop = "authenticated_emergency_stop"
  case cleanupUnproven = "cleanup_unproven"
}

public enum ProductM2SSHProofOutcome: String, Encodable, Equatable, Sendable {
  case notAttempted = "not_attempted"
  case proven
  case rejected
  case timedOut = "timed_out"
  case cancelled
}

package struct ProductM2NetworkBaseline: Equatable, Sendable {
  private enum Storage: Equatable, Sendable {
    case observed(NetworkCleanupSnapshot)
    case synthetic(UUID)
  }

  private let storage: Storage

  package init(identifier: UUID = UUID()) {
    storage = .synthetic(identifier)
  }

  package init(snapshot: NetworkCleanupSnapshot) {
    storage = .observed(snapshot)
  }

  package var identifier: UUID? {
    guard case .synthetic(let identifier) = storage else { return nil }
    return identifier
  }

  package var snapshot: NetworkCleanupSnapshot? {
    guard case .observed(let snapshot) = storage else { return nil }
    return snapshot
  }

  package var helperGeneration: VendorHelperGenerationSnapshot? {
    snapshot?.helperGeneration
  }

  package static func stable(_ first: Self, _ second: Self) -> Bool {
    guard let first = first.snapshot, let second = second.snapshot else { return false }
    return NetworkCleanupAssessment.baselineStable(first, second)
  }
}

public struct ProductM2CleanupEvidence: Encodable, Equatable, Sendable {
  public let complete: Bool
  public let defaultRouteRestored: Bool
  public let dnsRestored: Bool
  public let interfacesRestored: Bool
  public let utunRestored: Bool
  public let persistentRoutesRestored: Bool
  public let selectedRouteResidueCount: Int
  public let surgeStateRestored: Bool
  public let vendorProcessesRestored: Bool
  public let helperGenerationRestored: Bool
  public let structuralRouteTablesEqual: Bool
  public let containsRawRoutes = false
  public let containsRawState = false

  public init(
    complete: Bool = true,
    defaultRouteRestored: Bool,
    dnsRestored: Bool,
    interfacesRestored: Bool,
    utunRestored: Bool,
    persistentRoutesRestored: Bool = true,
    selectedRouteResidueCount: Int = 0,
    surgeStateRestored: Bool,
    vendorProcessesRestored: Bool = true,
    helperGenerationRestored: Bool,
    structuralRouteTablesEqual: Bool = true
  ) {
    self.complete = complete
    self.defaultRouteRestored = defaultRouteRestored
    self.dnsRestored = dnsRestored
    self.interfacesRestored = interfacesRestored
    self.utunRestored = utunRestored
    self.persistentRoutesRestored = persistentRoutesRestored
    self.selectedRouteResidueCount = selectedRouteResidueCount
    self.surgeStateRestored = surgeStateRestored
    self.vendorProcessesRestored = vendorProcessesRestored
    self.helperGenerationRestored = helperGenerationRestored
    self.structuralRouteTablesEqual = structuralRouteTablesEqual
  }

  public var allDimensionsRestored: Bool {
    complete && defaultRouteRestored && dnsRestored && interfacesRestored
      && utunRestored && persistentRoutesRestored
      && selectedRouteResidueCount == 0 && surgeStateRestored
      && vendorProcessesRestored && helperGenerationRestored
      && structuralRouteTablesEqual
  }

  package static let unavailable = Self(
    complete: false,
    defaultRouteRestored: false,
    dnsRestored: false,
    interfacesRestored: false,
    utunRestored: false,
    persistentRoutesRestored: false,
    surgeStateRestored: false,
    vendorProcessesRestored: false,
    helperGenerationRestored: false,
    structuralRouteTablesEqual: false
  )

  package init(_ result: NetworkCleanupResult) {
    self.init(
      complete: result.complete,
      defaultRouteRestored: result.defaultRouteRestored,
      dnsRestored: result.dnsRestored,
      interfacesRestored: result.interfacesRestored,
      utunRestored: result.utunRestored,
      persistentRoutesRestored: result.persistentRoutesRestored,
      selectedRouteResidueCount: result.selectedRouteResidueCount,
      surgeStateRestored: result.surgeStateRestored,
      vendorProcessesRestored: result.vendorProcessesRestored,
      helperGenerationRestored: result.helperGenerationRestored,
      structuralRouteTablesEqual: result.structuralRouteTablesEqual
    )
  }
}

public struct ProductM2ConnectRequest: Equatable, Sendable {
  public let resourceDisplayName: String
  public let sshTarget: ProductM2SSHTarget

  public init(resourceDisplayName: String, sshTarget: ProductM2SSHTarget) {
    self.resourceDisplayName = resourceDisplayName
    self.sshTarget = sshTarget
  }
}

public struct ProductM2ConnectReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 8
  public let outcome: ProductM2ConnectOutcome
  public let finalState: ProductM2ConnectionState
  public let lastGoodState: ProductM2ConnectionState
  public let firstBadEvent: ProductM2BadEvent?
  public let resourceDisplayName: String
  public let sshTarget: ProductM2SSHTarget
  public let authorizationSource: ProductM2AuthorizationSource
  public let authorizationAcquisition: ProductM2AuthorizationAcquisitionOutcome
  public let authorizationFailure: ProductM2AuthorizationFailure?
  public let startOutcome: ProductM2ControlOutcome
  public let vendorStatusEvidence: ProductM2VendorStatusEvidence
  public let activeNetworkEvidence: ProductM2ActiveNetworkEvidence
  public let sshProof: ProductM2SSHProofOutcome
  public let sshProofEvidence: ProductM2FreshSSHProofEvidence?
  public let cleanupPath: ProductM2CleanupPath
  public let stopOutcome: ProductM2ControlOutcome
  public let emergencyStopOutcome: ProductM2ControlOutcome
  public let authorizationClose: ProductM2AuthorizationCloseOutcome
  public let authorizationOwnedMaterialErased: Bool
  public let cleanupEvidence: ProductM2CleanupEvidence
  public let cleanupVerified: Bool
  public let serverContactRequested: Bool
  public let helperMutationRequested: Bool
  public let automaticRetryCount = 0
  public let containsSecrets = false
  public let snapshotSerialized = false
  /// Approval mode the CLI used before invoking the runtime:
  /// "tty_code" (operator typed the generated code) or "non_interactive"
  /// (credentials came from a protected file; no TTY approval). Nil when the
  /// report was produced without a CLI approval stage (runtime-only tests).
  public var approvalMode: String? = nil
}
