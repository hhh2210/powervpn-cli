import Foundation
import PowerVPNPortal

public enum ProductPortalDryRunOutcome: String, Encodable, Equatable, Sendable {
  case accepted
  case invalidRequest = "invalid_request"
  case portalAcquisitionRejected = "portal_acquisition_rejected"
  case resourceCatalogRejected = "resource_catalog_rejected"
  case resourceNotFound = "resource_not_found"
  case resourceAmbiguous = "resource_ambiguous"
  case startSnapshotIncomplete = "start_snapshot_incomplete"
  case startSnapshotRejected = "start_snapshot_rejected"
  case targetRouteNotCovered = "target_route_not_covered"
  case logoutRejected = "logout_rejected"
  case ownedMaterialEraseRejected = "owned_material_erase_rejected"
  case cancelled
}

public enum ProductPortalAcquisitionStatus: String, Encodable, Equatable, Sendable {
  case notRequested = "not_requested"
  case accepted
  case configurationRejected = "configuration_rejected"
  case credentialInputRejected = "credential_input_rejected"
  case transportRejected = "transport_rejected"
  case tlsRejected = "tls_rejected"
  case redirectRejected = "redirect_rejected"
  case loginRejected = "login_rejected"
  case challengeRequired = "challenge_required"
  case loginResponseRejected = "login_response_rejected"
  case sessionRejected = "session_rejected"
  case resourceListRejected = "resource_list_rejected"
  case authenticatedSnapshotRejected = "authenticated_snapshot_rejected"
  case logoutRejected = "logout_rejected"
  case cancelled
  case internalFailure = "internal_failure"
}

public enum ProductPortalDryRunLogoutOutcome: String, Encodable, Equatable, Sendable {
  case notRequired = "not_required"
  case accepted
  case rejected
  case timedOut = "timed_out"
  case cancelled
  case alreadyClosed = "already_closed"
}

/// Stage at which catalog mapping failed. Scope failures precede every
/// per-resource mapping; resource failures carry the failing `NC_RESOURCE`
/// entry's position.
public enum ProductResourceCatalogFailureStage: String, Encodable, Equatable, Sendable {
  case scope
  case resource
}

/// Closed, value-free classification of a catalog-mapping failure. Tokens are
/// fixed enum strings plus structural field paths only; no Portal response
/// bytes, display names, or values of any kind are representable here.
///
/// Official-contract context (PowerVPN 3.2.1 (24572) static dossier,
/// 2026-08-14): the official SP2 mapping parses no integer except the
/// per-tunnel status `intValue` gate (`0x100067846`–`0x1000678b7`) and copies
/// `SERVER@port`, lifetimes, `authority`, `family`, `negotiate-mode` as raw
/// strings; `VERSION@major` is string-compared (`'1'`→SP2 parser, `'0'`→SP1,
/// `'2'`→SP3; `0x1000aa4af`, `0x1000656f4`–`0x10006580c`), and XMLReader
/// renders an attribute-plus-child collision as `[attributeValue, childDict]`
/// (`0x100135459`–`0x1001354c0`). This taxonomy is therefore diagnostic only:
/// it names where our stricter native predicate rejected a leaf the official
/// contract tolerates, without loosening any predicate. `integer_invalid`
/// plus `fieldPath` pinpoints the exact strict-decimal leaf.
public enum ProductResourceCatalogFailureClass: String, Encodable, Equatable, Sendable {
  // Mapping-scope failures: context, list, or VERSION@major shape.
  case snapshotInaccessible = "snapshot_inaccessible"
  case integrationInfoMissing = "integration_info_missing"
  case resourceListMissing = "resource_list_missing"
  case resourceListDuplicate = "resource_list_duplicate"
  case majorVersionMissing = "major_version_missing"
  case majorVersionDuplicate = "major_version_duplicate"
  case majorVersionMalformed = "major_version_malformed"
  case majorVersionInvalid = "major_version_invalid"
  // Per-NC_RESOURCE failures.
  case duplicateField = "duplicate_field"
  case displayNameMissing = "display_name_missing"
  case displayNameInvalid = "display_name_invalid"
  case integerInvalid = "integer_invalid"
  case materialTooLarge = "material_too_large"
  // Defensive total classification for otherwise-unmapped throw sites.
  case unclassified
}

public struct ProductResourceCatalogFailure: Encodable, Equatable, Sendable {
  public let stage: ProductResourceCatalogFailureStage
  public let failureClass: ProductResourceCatalogFailureClass
  /// One-based position of the failing `NC_RESOURCE` entry within the
  /// resource list ("entry 2" is the second entry); nil for scope-stage
  /// failures.
  public let resourceOrdinal: Int?
  /// Structural field path (element/attribute names only, never values).
  public let fieldPath: String?
}

/// Value-free classification of a rejected logout. Distinct from
/// `ProductPortalDryRunLogoutOutcome` so schema-2 outcome meanings are
/// unchanged; only the rejected outcome carries a class.
///
/// Official-contract context (PowerVPN 3.2.1 (24572) static dossier,
/// 2026-08-14, `-[VSGAuthManager logout]` `0x1000a6810`): the official
/// completion block (`0x1000a6a80`) never reads its `NSError` slot or the
/// parsed object — it deletes every `VSG_SESSIONID` cookie
/// (`0x1000a6af1`–`0x1000a6cc0`), reports literal `0` to the delegate
/// (`0x1000a6d7a`–`0x1000a6def`), and clears cookies. So a completed remote
/// exchange is officially non-failing regardless of status; our native
/// acceptance still requires exactly HTTP 200 (a separate compatibility
/// decision), and local erasure stays unconditional.
public enum ProductPortalLogoutFailureClass: String, Encodable, Equatable, Sendable {
  case requestConstructionFailed = "request_construction_failed"
  case transportFailed = "transport_failed"
  case completedRemoteExchange = "completed_remote_exchange"
}

public struct ProductPortalDryRunOperations: Encodable, Equatable, Sendable {
  public let portalAcquisitionRequested: Bool
  public let loginRequested: Bool
  public let loginAccepted: Bool
  public let resourceListRequested: Bool
  public let resourceListAccepted: Bool
  public let sessionCheckRequested: Bool
  public let sessionCheckAccepted: Bool
  public let startSnapshotValidationRequested: Bool
  public let startSnapshotConstructed: Bool
  public let targetRouteValidationRequested: Bool
  public let logoutAttempted: Bool
  public let logoutAccepted: Bool
}

public struct ProductPortalDryRunRequest: Equatable, Sendable {
  public let resourceDisplayName: String
  public let sshTarget: ProductM2SSHTarget

  public init(resourceDisplayName: String, sshTarget: ProductM2SSHTarget) {
    self.resourceDisplayName = resourceDisplayName
    self.sshTarget = sshTarget
  }
}

public struct ProductPortalDryRunReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 2
  public let outcome: ProductPortalDryRunOutcome
  public let portalAcquisitionStatus: ProductPortalAcquisitionStatus
  public let portalTransportFailure: PortalTransportFailureEvidence?
  public let operations: ProductPortalDryRunOperations
  public let candidateCount: Int
  public let matchingCandidateCount: Int
  public let selectedCandidateCount: Int
  public let startSnapshotComplete: Bool
  public let targetRouteCovered: Bool
  public let logoutOutcome: ProductPortalDryRunLogoutOutcome
  public let ownedMaterialErased: Bool
  public let resourceCatalogFailure: ProductResourceCatalogFailure?
  public let logoutFailureClass: ProductPortalLogoutFailureClass?
  public let dryRunAccepted: Bool
  public let helperMutationRequested = false
  public let sshRequested = false
  public let m2CoordinatorRequested = false
  public let containsSecrets = false

  package init(
    outcome: ProductPortalDryRunOutcome,
    portalAcquisitionStatus: ProductPortalAcquisitionStatus,
    portalTransportFailure: PortalTransportFailureEvidence? = nil,
    operations: ProductPortalDryRunOperations,
    candidateCount: Int,
    matchingCandidateCount: Int,
    selectedCandidateCount: Int,
    startSnapshotComplete: Bool,
    targetRouteCovered: Bool,
    logoutOutcome: ProductPortalDryRunLogoutOutcome,
    ownedMaterialErased: Bool,
    resourceCatalogFailure: ProductResourceCatalogFailure? = nil,
    logoutFailureClass: ProductPortalLogoutFailureClass? = nil
  ) {
    self.outcome = outcome
    self.portalAcquisitionStatus = portalAcquisitionStatus
    self.portalTransportFailure =
      portalAcquisitionStatus == .accepted ? nil : portalTransportFailure
    self.operations = operations
    self.candidateCount = candidateCount
    self.matchingCandidateCount = matchingCandidateCount
    self.selectedCandidateCount = selectedCandidateCount
    self.startSnapshotComplete = startSnapshotComplete
    self.targetRouteCovered = targetRouteCovered
    self.logoutOutcome = logoutOutcome
    self.ownedMaterialErased = ownedMaterialErased
    self.resourceCatalogFailure = resourceCatalogFailure
    self.logoutFailureClass = logoutFailureClass
    dryRunAccepted =
      outcome == .accepted
      && portalAcquisitionStatus == .accepted
      && startSnapshotComplete
      && targetRouteCovered
      && logoutOutcome == .accepted
      && ownedMaterialErased
  }
}
