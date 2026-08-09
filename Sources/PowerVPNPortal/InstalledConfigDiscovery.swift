import CoreFoundation
import Darwin
import Foundation

public enum InstalledConfigDiscovery {
  /// Discovers the one sealed profile for this installed PowerVPN build. It
  /// deliberately accepts no arguments and reads no environment variables.
  public static func discoverCurrentMachine() throws -> InstalledPortalProfile {
    try discover(evidence: InstalledConfigEvidence.currentMachine(), owner: getuid())
  }

  static func discover(
    evidence: InstalledConfigEvidence,
    owner: uid_t
  ) throws -> InstalledPortalProfile {
    try validateManifest(evidence.artifacts)
    var preferences: Data?
    for artifact in evidence.artifacts {
      let read = try BoundedInstalledArtifactReader.read(
        artifact,
        owner: owner,
        captureData: artifact.role == .preferences
      )
      guard read.sha256 == artifact.sha256 else {
        throw InstalledConfigDiscoveryError.hashMismatch
      }
      if artifact.role == .preferences {
        preferences = read.capturedData
      }
    }
    guard let preferences else {
      throw InstalledConfigDiscoveryError.malformedEvidence
    }
    try validatePreferences(in: preferences)
    return try materialize(evidence.endpoint)
  }

  private static func validateManifest(_ artifacts: [InstalledArtifactSpec]) throws {
    guard
      !artifacts.contains(where: {
        URL(fileURLWithPath: $0.path).lastPathComponent == "resource.xml"
      })
    else {
      throw InstalledConfigDiscoveryError.forbiddenArtifact
    }
    guard artifacts.count == InstalledArtifactRole.allCases.count,
      Set(artifacts.map(\.role)) == Set(InstalledArtifactRole.allCases),
      artifacts.allSatisfy({
        $0.path.hasPrefix("/") && $0.maximumByteCount > 0 && isSHA256($0.sha256)
      })
    else {
      throw InstalledConfigDiscoveryError.malformedEvidence
    }
  }

  private static func validatePreferences(in data: Data) throws {
    let decoded: Any
    do {
      decoded = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    } catch {
      throw InstalledConfigDiscoveryError.malformedPreferences
    }
    guard let dictionary = decoded as? [String: Any],
      let selected = dictionary["address_selectedID"] as? NSNumber,
      CFGetTypeID(selected) != CFBooleanGetTypeID(),
      !CFNumberIsFloatType(selected),
      selected.int64Value == 0,
      selected.doubleValue == 0
    else {
      throw InstalledConfigDiscoveryError.selectedAddressMismatch
    }
    guard dictionary["currentLanguageKey"] as? String == "en-US" else {
      throw InstalledConfigDiscoveryError.languageMismatch
    }
  }

  private static func materialize(
    _ endpoint: SealedPortalEndpoint
  ) throws -> InstalledPortalProfile {
    guard endpoint.scheme == "https",
      endpoint.host == "166.111.143.19",
      endpoint.port == 4_443,
      endpoint.portalVersion == "2.0",
      endpoint.selectionSemantics == .latestPrimaryKeyFallback
    else {
      throw InstalledConfigDiscoveryError.endpointMismatch
    }
    var components = URLComponents()
    components.scheme = endpoint.scheme
    components.host = endpoint.host
    components.port = endpoint.port
    guard let origin = components.url,
      origin.absoluteString == "https://166.111.143.19:4443"
    else {
      throw InstalledConfigDiscoveryError.endpointMismatch
    }
    return InstalledPortalProfile(
      origin: origin,
      portalVersion: endpoint.portalVersion,
      selectionSemantics: endpoint.selectionSemantics,
      // The vendor compares "en-US" against ["", "zh-Hans", "en"]
      // exactly, misses, and therefore returns its default index zero.
      vendorLanguageIndex: 0
    )
  }

  private static func isSHA256(_ value: String) -> Bool {
    value.utf8.count == 64
      && value.utf8.allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
      }
  }
}
