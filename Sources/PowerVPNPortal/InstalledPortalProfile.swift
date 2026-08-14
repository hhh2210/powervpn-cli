import Foundation

public enum PortalAddressSelectionSemantics: String, Sendable {
  case latestPrimaryKeyFallback = "latest_pk_fallback"
  case operatorApprovedFixedOrigin = "operator_approved_fixed_origin"
}

/// A non-secret endpoint authority created only by internal validated sources:
/// either sealed installed evidence or the operator-approved fixed profile.
/// There is no public initializer for caller-supplied gateway or port input.
public struct InstalledPortalProfile: Equatable, Sendable {
  public let origin: URL
  public let portalVersion: String
  public let selectionSemantics: PortalAddressSelectionSemantics
  let vendorLanguageIndex: Int
}

public enum InstalledConfigDiscoveryError: Error, Equatable, Sendable {
  case malformedEvidence
  case forbiddenArtifact
  case missingArtifact
  case symbolicLink
  case notRegularFile
  case ownerMismatch
  case modeMismatch
  case sizeOutOfBounds
  case hashMismatch
  case readFailed
  case malformedPreferences
  case selectedAddressMismatch
  case languageMismatch
  case endpointMismatch
}
