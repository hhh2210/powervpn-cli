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
  case routeActivationRejected = "route_activation_rejected"
  /// Pre-schema-11 host-evidence gate: the active capture failed completeness.
  /// Since schema 11 the capture is diagnostic-only and the fresh SSH proof
  /// decides (`sshProofRejected`); no live path emits this outcome.
  case activeNetworkUnproven = "active_network_unproven"
  case sshProofRejected = "ssh_proof_rejected"
  case deadlineExceeded = "deadline_exceeded"
  case cancelled
  case cleanupUnproven = "cleanup_unproven"
}

public enum ProductM2SelectionFailureClass: String, Encodable, Equatable, Sendable {
  case catalogMapping = "catalog_mapping"
  case catalogEmpty = "catalog_empty"
  case catalogInvariantInvalid = "catalog_invariant_invalid"
  case prepareRemap = "prepare_remap"
  case selectionReplay = "selection_replay"
  case preparedSelectionMismatch = "prepared_selection_mismatch"
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
  case routeActivationRejected = "route_activation_rejected"
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
  case helperRejected = "helper_rejected"
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

/// Which evidence channel proved the tunnel's network effect (schema 11).
/// `ssh_banner`: a fresh SSH banner through the tunnel proved it — the
/// decisive channel since schema 11. `host_evidence`: the host-side active
/// capture assessment proved it while no SSH proof had been attempted
/// (persistent open reports, work-aborted connect-once runs). `none`: the
/// proof stage ran and nothing proved the network effect.
public enum ProductM2NetworkProofSource: String, Encodable, Equatable, Sendable {
  case sshBanner = "ssh_banner"
  case hostEvidence = "host_evidence"
  case none
}

/// Closed-set classification of the active-network capture stage, mapped from
/// the observer's `NetworkCleanupObservationState` tokens plus the synthetic
/// not-attempted / measured-incomplete / measured-complete summary states.
/// Purely diagnostic: it never feeds a gate.
public enum ProductM2ActiveCaptureState: String, Encodable, Equatable, Sendable {
  case notAttempted = "not_attempted"
  case commandFailed = "command_failed"
  case outputTooLarge = "output_too_large"
  case invalidOutput = "invalid_output"
  case changedDuringCapture = "changed_during_capture"
  case measuredIncomplete = "measured_incomplete"
  case measuredComplete = "measured_complete"
}

/// Axes of the active-capture snapshot that did not observe cleanly. The
/// effective-route probe folds into `ipv4Routes` (it is part of that snapshot's
/// `isObserved` predicate); helper process-set churn splits into
/// `helperProcesses` (surge inventory) versus `vendorProcesses` (vendor
/// inventory) exactly like the observer's A/B stability switches.
public enum ProductM2ActiveCaptureChangeAxis: String, Encodable, Equatable, Sendable {
  case helperGeneration = "helper_generation"
  case helperProcesses = "helper_processes"
  case defaultRoute = "default_route"
  case dns
  case interfaces
  case ipv4Routes = "ipv4_routes"
  case ipv6Routes = "ipv6_routes"
  case vendorProcesses = "vendor_processes"
}

/// Why a fully-measured capture still failed the completeness predicate.
public enum ProductM2ActiveCaptureIncompleteReason: String, Encodable, Equatable, Sendable {
  case generationNotExact = "generation_not_exact"
  case vendorProcessesInconsistent = "vendor_processes_inconsistent"
  case subobservationFailed = "subobservation_failed"
}

/// Read-only classification of a stop whose XPC outcome was
/// `connection_invalid`, comparing the pre-start cold generation with one
/// bounded post-stop generation re-observation. Diagnostic only.
public enum ProductM2StopInvalidityClass: String, Encodable, Equatable, Sendable {
  case helperExitedSingleGeneration = "helper_exited_single_generation"
  case helperRestarted = "helper_restarted"
  case helperRunningSessionInvalid = "helper_running_session_invalid"
  case unclassified

  package init(
    coldGeneration: VendorHelperGenerationSnapshot,
    postStopGeneration: VendorHelperGenerationSnapshot
  ) {
    if ProductM2GenerationFence.singleExitedGeneration(coldGeneration, postStopGeneration) {
      self = .helperExitedSingleGeneration
    } else if ProductM2GenerationFence.singleRunningGeneration(
      coldGeneration, postStopGeneration
    ) {
      self = .helperRunningSessionInvalid
    } else if coldGeneration.exactInactive,
      let coldRuns = coldGeneration.runs, coldRuns < Int.max,
      let postRuns = postStopGeneration.runs, postRuns > coldRuns + 1
    {
      self = .helperRestarted
    } else {
      self = .unclassified
    }
  }
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
  public let schemaVersion = 13
  public let outcome: ProductM2ConnectOutcome
  public let finalState: ProductM2ConnectionState
  public let lastGoodState: ProductM2ConnectionState
  public let firstBadEvent: ProductM2BadEvent?
  public let resourceDisplayName: String
  public let sshTarget: ProductM2SSHTarget
  public let authorizationSource: ProductM2AuthorizationSource
  public let authorizationAcquisition: ProductM2AuthorizationAcquisitionOutcome
  public let authorizationFailure: ProductM2AuthorizationFailure?
  public let resourceCatalogFailure: ProductResourceCatalogFailure?
  public let selectionFailureClass: ProductM2SelectionFailureClass?
  public let startOutcome: ProductM2ControlOutcome
  /// Bounded value-free signatures with global arrival ordinal and channel.
  public var startEventSignatures: [String]? = nil
  public var startReplySignatures: [String]? = nil
  /// Exact key/type signature of the event that terminally rejected start.
  public var unexpectedEventSignature: [String]? = nil
  public let vendorStatusEvidence: ProductM2VendorStatusEvidence
  /// Value-free acknowledgement evidence for the post-connected NC route toggle.
  public var routeActivationOutcome: ProductM2ControlOutcome = .notAttempted
  public var routeActivationRequestSent = false
  public var routeActivationAcknowledged = false
  public var routeActivationPeerGenerationValidated = false
  public let activeNetworkEvidence: ProductM2ActiveNetworkEvidence
  /// Diagnostic classification of the active-network capture stage
  /// (schema 10). Nil — omitted from JSON — when the run never reached the
  /// active-capture stage.
  public var activeCaptureState: ProductM2ActiveCaptureState? = nil
  /// Snapshot axes that did not observe cleanly during the active capture.
  /// Nil when every axis observed (or the stage never ran).
  public var activeCaptureChangeAxes: [ProductM2ActiveCaptureChangeAxis]? = nil
  /// Why a fully-measured active capture still failed completeness.
  public var activeCaptureIncompleteReason: ProductM2ActiveCaptureIncompleteReason? = nil
  public let sshProof: ProductM2SSHProofOutcome
  public let sshProofEvidence: ProductM2FreshSSHProofEvidence?
  /// Which channel proved the tunnel's network effect (schema 11). Nil —
  /// omitted from JSON — when the run never reached the network-proof stage.
  public var networkProofSource: ProductM2NetworkProofSource? = nil
  public let cleanupPath: ProductM2CleanupPath
  public let stopOutcome: ProductM2ControlOutcome
  /// Value-free acknowledgement evidence for the pre-stop NC route toggle.
  public var routeDeactivationOutcome: ProductM2ControlOutcome = .notAttempted
  public var routeDeactivationRequestSent = false
  public var routeDeactivationAcknowledged = false
  public var routeDeactivationPeerGenerationValidated = false
  /// Read-only classification of a `connection_invalid` stop via one bounded
  /// post-stop generation re-observation (schema 10). Nil when the stop was
  /// not `connection_invalid`.
  public var stopInvalidityClass: ProductM2StopInvalidityClass? = nil
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
