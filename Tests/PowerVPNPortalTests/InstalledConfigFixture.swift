import CryptoKit
import Darwin
import Foundation

@testable import PowerVPNPortal

final class InstalledConfigFixture {
  let root: URL
  private(set) var evidence: InstalledConfigEvidence

  init(selectedAddress: Any = 0) throws {
    root = FileManager.default.temporaryDirectory
      .appendingPathComponent("powervpn-r2-config-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

    let files: [(InstalledArtifactRole, String, Data, mode_t)] = [
      (.appExecutable, "PowerVPN", Data("synthetic-app".utf8), 0o755),
      (.appInfoPlist, "Info.plist", Data("synthetic-info".utf8), 0o644),
      (.encryptedAddressDatabase, "users.sqlite", Data("encrypted-db".utf8), 0o644),
      (.preferences, "preferences.plist", try Self.preferences(selectedAddress), 0o600),
    ]
    var artifacts: [InstalledArtifactSpec] = []
    for (role, name, data, mode) in files {
      let url = root.appendingPathComponent(name)
      try data.write(to: url)
      guard chmod(url.path, mode) == 0 else { throw FixtureError.setupFailed }
      artifacts.append(
        InstalledArtifactSpec(
          role: role,
          path: url.path,
          sha256: Self.sha256(data),
          mode: mode,
          maximumByteCount: 4_096
        ))
    }
    evidence = InstalledConfigEvidence(artifacts: artifacts, endpoint: Self.lockedEndpoint)
  }

  func cleanup() {
    try? FileManager.default.removeItem(at: root)
  }

  func url(for role: InstalledArtifactRole) -> URL {
    URL(fileURLWithPath: evidence.artifacts.first(where: { $0.role == role })!.path)
  }

  func replaceEvidence(
    artifacts: [InstalledArtifactSpec]? = nil,
    endpoint: SealedPortalEndpoint? = nil
  ) {
    evidence = InstalledConfigEvidence(
      artifacts: artifacts ?? evidence.artifacts,
      endpoint: endpoint ?? evidence.endpoint
    )
  }

  func replaceArtifact(
    _ role: InstalledArtifactRole,
    path: String? = nil,
    sha256: String? = nil
  ) {
    let changed = evidence.artifacts.map { spec in
      guard spec.role == role else { return spec }
      return InstalledArtifactSpec(
        role: spec.role,
        path: path ?? spec.path,
        sha256: sha256 ?? spec.sha256,
        mode: spec.mode,
        maximumByteCount: spec.maximumByteCount
      )
    }
    replaceEvidence(artifacts: changed)
  }

  func rewritePreferences(selectedAddress: Any) throws {
    let data = try Self.preferences(selectedAddress)
    let url = url(for: .preferences)
    try data.write(to: url)
    guard chmod(url.path, 0o600) == 0 else { throw FixtureError.setupFailed }
    replaceArtifact(.preferences, sha256: Self.sha256(data))
  }

  static let lockedEndpoint = SealedPortalEndpoint(
    scheme: "https",
    host: "166.111.143.19",
    port: 4_443,
    portalVersion: "2.0",
    selectionSemantics: .latestPrimaryKeyFallback
  )

  static func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private static func preferences(_ selectedAddress: Any) throws -> Data {
    try PropertyListSerialization.data(
      fromPropertyList: [
        "address_selectedID": selectedAddress,
        "currentLanguageKey": "en-US",
        "unrelated": "retained",
      ],
      format: .binary,
      options: 0
    )
  }
}

enum FixtureError: Error {
  case setupFailed
}
