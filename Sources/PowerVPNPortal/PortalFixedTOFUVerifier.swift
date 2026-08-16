import CPortalCurl
import Foundation

enum PortalTrustMode: String, Sendable {
  case operatorApprovedTOFU = "operator_approved_tofu"
}

/// The operator-approved local-MVP trust authority. The endpoint comes from
/// targets.json; peer-chain validation and the immutable SPKI pin remain fixed.
struct PortalFixedTOFUVerifier: Sendable {
  static let spkiSHA256Hex =
    "b7d82d5baa74d6bc8e45062475b54e81ebd2d2cabb6d01e0a0049677cd0eab54"
  static let curlPinnedPublicKey =
    String(cString: pvcurl_approved_pinned_public_key())
  static let trustMode = PortalTrustMode.operatorApprovedTOFU
  static let releaseReady = false

  let origin: PortalHTTPOrigin
  let profile: InstalledPortalProfile

  static func currentMachine() throws -> Self {
    try configured(PowerVPNTargetsConfiguration.currentMachine())
  }

  static func configured(_ configuration: PowerVPNTargetsConfiguration) throws -> Self {
    let profile = configuration.portalProfile
    guard let host = profile.origin.host, let port = profile.origin.port else {
      throw PortalTransportError.invalidOrigin
    }
    return Self(
      origin: try PortalHTTPOrigin(host: host, port: port),
      profile: profile
    )
  }

  private init(origin: PortalHTTPOrigin, profile: InstalledPortalProfile) {
    self.origin = origin
    self.profile = profile
  }
}

/// Read-only access to the same authority used by production Portal login.
public enum PortalFixedTOFUAuthority {
  public static func currentProfile() throws -> InstalledPortalProfile {
    try PortalFixedTOFUVerifier.currentMachine().profile
  }
}
