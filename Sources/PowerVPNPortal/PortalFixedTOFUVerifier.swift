import CPortalCurl
import Foundation

enum PortalTrustMode: String, Sendable {
  case operatorApprovedTOFU = "operator_approved_tofu"
}

/// The single operator-approved local-MVP trust authority. Production has no
/// initializer or input seam for replacing its origin or pin at runtime.
struct PortalFixedTOFUVerifier: Sendable {
  static let exactOrigin = "https://166.111.143.19:4443"
  static let spkiSHA256Hex =
    "b7d82d5baa74d6bc8e45062475b54e81ebd2d2cabb6d01e0a0049677cd0eab54"
  static let curlPinnedPublicKey =
    String(cString: pvcurl_approved_pinned_public_key())
  static let trustMode = PortalTrustMode.operatorApprovedTOFU
  static let releaseReady = false

  let origin: PortalHTTPOrigin
  let profile: InstalledPortalProfile

  static func currentMachine() throws -> Self {
    guard let url = URL(string: exactOrigin), url.absoluteString == exactOrigin else {
      throw PortalTransportError.invalidOrigin
    }
    return Self(
      origin: try PortalHTTPOrigin(host: "166.111.143.19", port: 4_443),
      profile: InstalledPortalProfile(
        origin: url,
        portalVersion: "2.0",
        selectionSemantics: .operatorApprovedFixedOrigin,
        // The fixed profile retains the protocol's proven language index.
        vendorLanguageIndex: 0
      )
    )
  }

  private init(origin: PortalHTTPOrigin, profile: InstalledPortalProfile) {
    self.origin = origin
    self.profile = profile
  }
}

/// Read-only access to the same immutable authority used by production Portal
/// login. Product readiness may validate this profile without consulting
/// mutable or stale installed preferences.
public enum PortalFixedTOFUAuthority {
  public static func currentProfile() throws -> InstalledPortalProfile {
    try PortalFixedTOFUVerifier.currentMachine().profile
  }
}
