import Foundation

public struct VendorBuildInfo: Codable, Equatable, Sendable {
  public let version: String
  public let build: String

  public init(version: String, build: String) {
    self.version = version
    self.build = build
  }
}

public struct VendorHelperArtifact: Codable, Equatable, Sendable {
  public let path: String
  public let architectures: [String]
  public let sha256: String
  public let vendorBuild: String

  public init(path: String, architectures: [String], sha256: String, vendorBuild: String) {
    self.path = path
    self.architectures = architectures
    self.sha256 = sha256
    self.vendorBuild = vendorBuild
  }
}

public struct OracleVersionFinding: Codable, Equatable, Sendable {
  public let value: String
  public let evidence: String

  public init(value: String, evidence: String) {
    self.value = value
    self.evidence = evidence
  }
}

public struct OracleEvidenceMarker: Codable, Equatable, Sendable {
  public let observed: Bool
  public let markers: [String]

  public init(markers: [String]) {
    observed = !markers.isEmpty
    self.markers = markers
  }
}

public struct VendorStaticEvidence: Codable, Equatable, Sendable {
  public let strongSwan: OracleEvidenceMarker
  public let leadsecbridge: OracleEvidenceMarker
  public let kernelLibIPSec: OracleEvidenceMarker
  public let kernelOSX: OracleEvidenceMarker
  public let xAuth: OracleEvidenceMarker
  public let modeConfig: OracleEvidenceMarker
  public let vici: OracleEvidenceMarker

  public init(
    strongSwan: OracleEvidenceMarker,
    leadsecbridge: OracleEvidenceMarker,
    kernelLibIPSec: OracleEvidenceMarker,
    kernelOSX: OracleEvidenceMarker,
    xAuth: OracleEvidenceMarker,
    modeConfig: OracleEvidenceMarker,
    vici: OracleEvidenceMarker
  ) {
    self.strongSwan = strongSwan
    self.leadsecbridge = leadsecbridge
    self.kernelLibIPSec = kernelLibIPSec
    self.kernelOSX = kernelOSX
    self.xAuth = xAuth
    self.modeConfig = modeConfig
    self.vici = vici
  }
}

public enum OracleClassificationState: String, Codable, Sendable {
  case confirmed
  case unknown
}

public struct LeadsecBridgeClassification: Codable, Equatable, Sendable {
  public let configurationAdapter: OracleClassificationState
  public let customStrongSwanPlugin: OracleClassificationState
  public let privateIKEv1ResourceRuleExtension: OracleClassificationState

  public init(
    configurationAdapter: OracleClassificationState = .unknown,
    customStrongSwanPlugin: OracleClassificationState,
    privateIKEv1ResourceRuleExtension: OracleClassificationState = .unknown
  ) {
    self.configurationAdapter = configurationAdapter
    self.customStrongSwanPlugin = customStrongSwanPlugin
    self.privateIKEv1ResourceRuleExtension = privateIKEv1ResourceRuleExtension
  }
}

public struct VendorHelperInventory: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let scope: String
  public let vendor: VendorBuildInfo
  public let helpers: [VendorHelperArtifact]
  public let loadedPlugins: [String]
  public let upstreamStrongSwanVersion: OracleVersionFinding
  public let vendorPatchLevel: String
  public let staticCapabilitySemantics: String
  public let staticEvidence: VendorStaticEvidence
  public let leadsecbridgeClassification: LeadsecBridgeClassification

  public init(
    vendor: VendorBuildInfo,
    helpers: [VendorHelperArtifact],
    loadedPlugins: [String],
    upstreamStrongSwanVersion: OracleVersionFinding,
    staticEvidence: VendorStaticEvidence,
    leadsecbridgeClassification: LeadsecBridgeClassification
  ) {
    schemaVersion = 1
    scope = "read_only_static_and_allowlisted_log_inventory"
    self.vendor = vendor
    self.helpers = helpers
    self.loadedPlugins = loadedPlugins
    self.upstreamStrongSwanVersion = upstreamStrongSwanVersion
    vendorPatchLevel = "unknown"
    staticCapabilitySemantics = "compiled_or_linked_evidence_only_not_negotiated"
    self.staticEvidence = staticEvidence
    self.leadsecbridgeClassification = leadsecbridgeClassification
  }
}
