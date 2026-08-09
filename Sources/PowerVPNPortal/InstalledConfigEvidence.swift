import Darwin
import Foundation

enum InstalledArtifactRole: String, CaseIterable, Hashable, Sendable {
  case appExecutable
  case appInfoPlist
  case encryptedAddressDatabase
  case preferences
}

struct InstalledArtifactSpec: Equatable, Sendable {
  let role: InstalledArtifactRole
  let path: String
  let sha256: String
  let mode: mode_t
  let maximumByteCount: Int
}

struct SealedPortalEndpoint: Equatable, Sendable {
  let scheme: String
  let host: String
  let port: Int
  let portalVersion: String
  let selectionSemantics: PortalAddressSelectionSemantics
}

struct InstalledConfigEvidence: Equatable, Sendable {
  let artifacts: [InstalledArtifactSpec]
  let endpoint: SealedPortalEndpoint

  /// The endpoint was derived read-only with the exact vendor SQLCipher 3.4.0
  /// build from VSGAddressModel's latest-primary-key fallback. Runtime code
  /// never decrypts this database; its exact hash seals that prior evidence.
  static func currentMachine() throws -> Self {
    guard let accountEntry = getpwuid(getuid()), let homePointer = accountEntry.pointee.pw_dir
    else {
      throw InstalledConfigDiscoveryError.malformedEvidence
    }
    let home = String(cString: homePointer)
    let applicationSupport = "\(home)/Library/Application Support/com.leadsec.PowerVPN-Mac"
    let preferences = "\(home)/Library/Preferences/com.leadsec.PowerVPN-Mac.plist"

    return Self(
      artifacts: [
        InstalledArtifactSpec(
          role: .appExecutable,
          path: "/Applications/PowerVPN.app/Contents/MacOS/PowerVPN",
          sha256: "069dee7b624ff2d8a3714bfed06aa6444ad45406d102b5933b987b88a39c7a46",
          mode: 0o755,
          maximumByteCount: 16 * 1_024 * 1_024
        ),
        InstalledArtifactSpec(
          role: .appInfoPlist,
          path: "/Applications/PowerVPN.app/Contents/Info.plist",
          sha256: "17dcebf8c12a45e8a4647df070d5abe15f0cc94c89c144a89cc7d53a631146dd",
          mode: 0o644,
          maximumByteCount: 64 * 1_024
        ),
        InstalledArtifactSpec(
          role: .encryptedAddressDatabase,
          path: "\(applicationSupport)/Users/users.sqlite",
          sha256: "7fcf73eef83bb9b39eac6da8c15a381cc596b95f75c9c0714e0a32345f529804",
          mode: 0o644,
          maximumByteCount: 1_024 * 1_024
        ),
        InstalledArtifactSpec(
          role: .preferences,
          path: preferences,
          sha256: "08e59cc23de9f196a5f7d2d8eb85000d09deca5b4d30c44a6c6c5232c9bd6d68",
          mode: 0o600,
          maximumByteCount: 64 * 1_024
        ),
      ],
      endpoint: SealedPortalEndpoint(
        scheme: "https",
        host: "166.111.143.19",
        port: 4_443,
        portalVersion: "2.0",
        selectionSemantics: .latestPrimaryKeyFallback
      )
    )
  }
}
