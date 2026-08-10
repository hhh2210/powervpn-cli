import Foundation

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
  case portalAcquisitionRejected = "portal_acquisition_rejected"
  case resourceCatalogRejected = "resource_catalog_rejected"
  case resourceNotFound = "resource_not_found"
  case resourceAmbiguous = "resource_ambiguous"
  case generationFenceRejected = "generation_fence_rejected"
  case startSnapshotRejected = "start_snapshot_rejected"
  case startRejected = "start_rejected"
  case sshProofRejected = "ssh_proof_rejected"
  case cancelled
  case cleanupUnproven = "cleanup_unproven"
}

public enum ProductM2BadEvent: String, Encodable, Equatable, Sendable {
  case preflightRejected = "preflight_rejected"
  case networkBaselineUnavailable = "network_baseline_unavailable"
  case networkBaselineChanged = "network_baseline_changed"
  case portalAcquisitionRejected = "portal_acquisition_rejected"
  case resourceCatalogRejected = "resource_catalog_rejected"
  case resourceNotFound = "resource_not_found"
  case resourceAmbiguous = "resource_ambiguous"
  case generationFenceRejected = "generation_fence_rejected"
  case startSnapshotRejected = "start_snapshot_rejected"
  case startControlRejected = "start_control_rejected"
  case postStartGenerationRejected = "post_start_generation_rejected"
  case sshProofRejected = "ssh_proof_rejected"
  case cancelled
  case portalLogoutRejected = "portal_logout_rejected"
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

public enum ProductM2PortalAcquisitionOutcome: String, Encodable, Equatable, Sendable {
  case notRequested = "not_requested"
  case acquired
  case rejected
  case cancelled
}

public enum ProductM2PortalLogoutOutcome: String, Encodable, Equatable, Sendable {
  case notRequired = "not_required"
  case accepted
  case rejected
  case timedOut = "timed_out"
  case cancelled
  case alreadyClosed = "already_closed"
}

public enum ProductM2CleanupPath: String, Encodable, Equatable, Sendable {
  case notRequired = "not_required"
  case sameLeaseStop = "same_lease_stop"
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
  package let identifier: UUID

  package init(identifier: UUID = UUID()) {
    self.identifier = identifier
  }
}

public struct ProductM2CleanupEvidence: Encodable, Equatable, Sendable {
  public let defaultRouteRestored: Bool
  public let dnsRestored: Bool
  public let interfacesRestored: Bool
  public let utunRestored: Bool
  public let surgeStateRestored: Bool
  public let helperGenerationRestored: Bool

  public init(
    defaultRouteRestored: Bool,
    dnsRestored: Bool,
    interfacesRestored: Bool,
    utunRestored: Bool,
    surgeStateRestored: Bool,
    helperGenerationRestored: Bool
  ) {
    self.defaultRouteRestored = defaultRouteRestored
    self.dnsRestored = dnsRestored
    self.interfacesRestored = interfacesRestored
    self.utunRestored = utunRestored
    self.surgeStateRestored = surgeStateRestored
    self.helperGenerationRestored = helperGenerationRestored
  }

  public var allDimensionsRestored: Bool {
    defaultRouteRestored && dnsRestored && interfacesRestored
      && utunRestored && surgeStateRestored && helperGenerationRestored
  }

  package static let unavailable = Self(
    defaultRouteRestored: false,
    dnsRestored: false,
    interfacesRestored: false,
    utunRestored: false,
    surgeStateRestored: false,
    helperGenerationRestored: false
  )
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
  public let schemaVersion = 1
  public let outcome: ProductM2ConnectOutcome
  public let finalState: ProductM2ConnectionState
  public let lastGoodState: ProductM2ConnectionState
  public let firstBadEvent: ProductM2BadEvent?
  public let resourceDisplayName: String
  public let sshTarget: ProductM2SSHTarget
  public let portalAcquisition: ProductM2PortalAcquisitionOutcome
  public let startOutcome: ProductM2ControlOutcome
  public let sshProof: ProductM2SSHProofOutcome
  public let cleanupPath: ProductM2CleanupPath
  public let stopOutcome: ProductM2ControlOutcome
  public let emergencyStopOutcome: ProductM2ControlOutcome
  public let portalLogout: ProductM2PortalLogoutOutcome
  public let cleanupEvidence: ProductM2CleanupEvidence
  public let cleanupVerified: Bool
  public let serverContactRequested: Bool
  public let helperMutationRequested: Bool
  public let automaticRetryCount = 0
  public let containsSecrets = false
  public let snapshotSerialized = false
}
