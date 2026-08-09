import Foundation

public enum PortalAddressSelectionSemantics: String, Sendable {
  case latestPrimaryKeyFallback = "latest_pk_fallback"
}

/// A non-secret endpoint proven by the sealed, current-machine installation
/// evidence. There is intentionally no public initializer: callers cannot
/// turn gateway or port input into a compatibility profile.
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
