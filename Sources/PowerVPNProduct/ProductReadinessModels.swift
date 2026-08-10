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
  case authorizedResourceProviderUnavailable = "authorized_resource_provider_unavailable"
  case authenticatedPortalSnapshotUnavailable = "authenticated_portal_snapshot_unavailable"
  case authorizedResourceSnapshotIncomplete = "authorized_resource_snapshot_incomplete"
  case resourceCatalogInvalid = "resource_catalog_invalid"
  case resourceSelectionRequired = "resource_selection_required"
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
  public let firstMissingField: VendorCharonStartField?
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
  public let schemaVersion = 2
  public let productState: ProductState
  public let onboardingMode = ProductOnboardingMode.vendorOnce
  public let profileSource: ProductProfileSource
  public let resourceSource: ProductResourceSource
  public let selectableResourceCount: Int
  public let selectableResources: [ProductResourceSummary]
  public let blocker: ProductBlocker?
  public let containsSecrets = false
  public let serverContactRequested = false
}

public struct ProductResourceSummary: Encodable, Equatable, Sendable {
  public let handle: String
  public let displayName: String
}

public struct ProductResourceCandidate: Equatable, Sendable {
  public let summary: ProductResourceSummary
  let fieldReports: [VendorCharonStartFieldReport]
  let snapshotComplete: Bool
  let firstMissingField: VendorCharonStartField?
  let firstMissingPath: String?

  init(
    summary: ProductResourceSummary,
    validation: VendorCharonStartValidation
  ) {
    self.summary = summary
    fieldReports = validation.fieldReports
    snapshotComplete = validation.complete
    firstMissingField = validation.firstMissingField
    firstMissingPath = validation.firstMissingPath
  }
}

public struct VendorSnapshotFieldReport: Encodable, Equatable, Sendable {
  public let field: VendorCharonStartField
  public let requirement: VendorCharonStartFieldRequirement
  public let availability: VendorCharonStartFieldAvailability
  public let sources: [VendorCharonStartMaterialSource]
  public let firstIssuePath: String?
}

public struct ProductSnapshotDryRunReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 3
  public let productState: ProductState
  public let profileSource: ProductProfileSource
  public let resourceSource: ProductResourceSource
  public let selectedResource: ProductResourceSummary?
  public let fields: [VendorSnapshotFieldReport]
  public let snapshotComplete: Bool
  public let firstMissingField: VendorCharonStartField?
  public let blocker: ProductBlocker?
  public let snapshotSerialized = false
  public let containsSecrets = false
  public let serverContactRequested = false
  public let helperMutationRequested = false
}
