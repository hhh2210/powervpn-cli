import Foundation
import PowerVPNCore

public enum ProductState: String, Codable, Equatable, Sendable {
  case ready
  case degraded
  case blocked
}

public enum ProductOnboardingMode: String, Codable, Equatable, Sendable {
  case vendorOnce = "vendor_once"
}

public enum DirectXPCStatus: String, Codable, Equatable, Sendable {
  case currentReachable = "current_reachable"
  case currentUnreachable = "current_unreachable"
  case notProbed = "not_probed"
}

public enum ProductProfileSource: String, Codable, Equatable, Sendable {
  case sealedInstalledConfiguration = "sealed_installed_configuration"
  case unavailable
}

public enum ProductResourceSource: String, Codable, Equatable, Sendable {
  case authenticatedPortalSnapshot = "authenticated_portal_snapshot"
  case unavailable
}

public enum ProductBlocker: String, Codable, Equatable, Sendable {
  case powerVPNNotInstalled = "powervpn_not_installed"
  case officialGUIRunning = "official_gui_running"
  case helperUnavailable = "helper_unavailable"
  case helperGenerationUnavailable = "helper_generation_unavailable"
  case installedConfigurationUnavailable = "installed_configuration_unavailable"
  case directXPCNotProbed = "direct_xpc_not_probed"
  case directXPCUnreachable = "direct_xpc_unreachable"
  case directXPCPreflightUnsafe = "direct_xpc_preflight_unsafe"
  case authenticatedPortalSnapshotNotExposed = "authenticated_portal_snapshot_not_exposed"
  case authorizedResourceSnapshotIncomplete = "authorized_resource_snapshot_incomplete"
  case resourceCatalogInvalid = "resource_catalog_invalid"
  case resourceSelectionRequired = "resource_selection_required"
}

public enum VendorSnapshotField: String, Codable, CaseIterable, Equatable, Sendable {
  case type
  case rpc
  case common
  case tunnels
  case sessionID = "common.sessionid"
  case vip = "common.vip"
  case vipv6 = "common.vipv6"
  case gateway = "common.gateway"
  case ikePort = "common.ike_port"
  case majorVersion = "common.majorVersion"
  case ike = "common.ike"
  case esp = "common.esp"
  case psk = "common.psk"
  case ikeLifetime = "common.ike_life_time"
  case ipsecLifetime = "common.ipsec_life_time"
  case hostItem = "common.hostItem"
  case authority = "tunnels[].authority"
  case status = "tunnels[].status"
  case tunnelName = "tunnels[].tunnel-name"
  case family = "tunnels[].family"
  case resourceFlag = "tunnels[].rflag"
  case name = "tunnels[].name"
  case routes = "tunnels[].routes"
  case mapID = "tunnels[].mapid"
  case negotiateMode = "tunnels[].negotiate-mode"
  case routeNetwork = "tunnels[].routes[].net"
  case routePrefix = "tunnels[].routes[].prfix"

  public var required: Bool {
    switch self {
    case .vip, .vipv6, .hostItem, .negotiateMode: false
    default: true
    }
  }

  public var generatedEnvelope: Bool {
    self == .type || self == .rpc || self == .common || self == .tunnels
  }
}

public enum SnapshotFieldAvailability: String, Codable, Equatable, Sendable {
  case generated
  case available
  case missing
}

public enum SnapshotFieldSource: String, Codable, Equatable, Sendable {
  case generatedConstant = "generated_constant"
  case authenticatedPortalSnapshot = "authenticated_portal_snapshot"
  case unavailable
}

public struct ProductHelperGeneration: Encodable, Equatable, Sendable {
  public let launchdObserved: Bool
  public let running: Bool
  public let inactiveConfirmed: Bool
  public let activeCount: Int?
  public let runs: Int?

  init(_ snapshot: VendorHelperGenerationSnapshot) {
    launchdObserved = snapshot.launchdObserved
    running = snapshot.running
    inactiveConfirmed = snapshot.inactiveConfirmed
    activeCount = snapshot.activeCount
    runs = snapshot.runs
  }
}

public struct ProductDoctorReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 1
  public let productState: ProductState
  public let onboardingMode = ProductOnboardingMode.vendorOnce
  public let installedVersion: String?
  public let installedBuild: String?
  public let installedArchitectures: [String]
  public let officialGUIRunning: Bool
  public let helperAvailable: Bool
  public let profileSource: ProductProfileSource
  public let resourceSource: ProductResourceSource
  public let snapshotComplete: Bool
  public let firstMissingField: VendorSnapshotField?
  public let blocker: ProductBlocker?
  public let containsSecrets = false
  public let networkRequested = false
  public let helperMutationRequested = false
}

public struct ProductHelperStatusReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 1
  public let productState: ProductState
  public let helperAvailable: Bool
  public let generation: ProductHelperGeneration
  public let directXPCStatus: DirectXPCStatus
  public let liveProbePerformed: Bool
  public let probeAvailable: Bool
  public let preflightRequired = true
  public let preflightSafe: Bool
  public let blocker: ProductBlocker?
  public let serverContactRequested = false
  public let helperMutationRequested = false
}

public struct ProductResourcesReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 1
  public let productState: ProductState
  public let onboardingMode = ProductOnboardingMode.vendorOnce
  public let profileSource: ProductProfileSource
  public let resourceSource: ProductResourceSource
  public let selectableResourceCount: Int
  public let selectableResources: [String]
  public let blocker: ProductBlocker?
  public let containsSecrets = false
  public let serverContactRequested = false
}

public struct ProductResourceCandidate: Equatable, Sendable {
  public let name: String
  public let availableSnapshotFields: Set<VendorSnapshotField>

  public init(
    name: String,
    availableSnapshotFields: Set<VendorSnapshotField>
  ) {
    self.name = name
    self.availableSnapshotFields = availableSnapshotFields
  }
}

public struct VendorSnapshotFieldReport: Encodable, Equatable, Sendable {
  public let field: VendorSnapshotField
  public let required: Bool
  public let availability: SnapshotFieldAvailability
  public let source: SnapshotFieldSource
}

public struct ProductSnapshotDryRunReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 1
  public let productState: ProductState
  public let profileSource: ProductProfileSource
  public let resourceSource: ProductResourceSource
  public let selectedResource: String?
  public let fields: [VendorSnapshotFieldReport]
  public let snapshotComplete: Bool
  public let firstMissingField: VendorSnapshotField?
  public let blocker: ProductBlocker?
  public let snapshotSerialized = false
  public let containsSecrets = false
  public let serverContactRequested = false
  public let helperMutationRequested = false
}
