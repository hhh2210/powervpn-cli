import Darwin
import Foundation
import PowerVPNCore
import PowerVPNPortal

public struct ProductReadinessObservation: Equatable, Sendable {
  public let installedVersion: String?
  public let installedBuild: String?
  public let installedArchitectures: [String]
  public let officialGUIRunning: Bool
  public let helperAvailable: Bool
  public let generation: VendorHelperGenerationSnapshot
  public let directXPCStatus: DirectXPCStatus
  public let directXPCPreflightSafe: Bool
  public let profileSource: ProductProfileSource
  public let resourceSource: ProductResourceSource
  public let resourceCandidates: [ProductResourceCandidate]

  public init(
    installedVersion: String?,
    installedBuild: String?,
    installedArchitectures: [String],
    officialGUIRunning: Bool,
    helperAvailable: Bool,
    generation: VendorHelperGenerationSnapshot,
    directXPCStatus: DirectXPCStatus,
    directXPCPreflightSafe: Bool,
    profileSource: ProductProfileSource,
    resourceSource: ProductResourceSource,
    resourceCandidates: [ProductResourceCandidate]
  ) {
    self.installedVersion = installedVersion
    self.installedBuild = installedBuild
    self.installedArchitectures = installedArchitectures
    self.officialGUIRunning = officialGUIRunning
    self.helperAvailable = helperAvailable
    self.generation = generation
    self.directXPCStatus = directXPCStatus
    self.directXPCPreflightSafe = directXPCPreflightSafe
    self.profileSource = profileSource
    self.resourceSource = resourceSource
    self.resourceCandidates = resourceCandidates
  }
}

public protocol ProductReadinessObserving: Sendable {
  func observe() -> ProductReadinessObservation
}

public struct InstalledProductReadinessObserver: ProductReadinessObserving {
  private static let helperPath =
    "/Library/PrivilegedHelperTools/com.leadsec.charon-xpc"

  public init() {}

  public func observe() -> ProductReadinessObservation {
    let installation = SystemInspector().installation()
    let generation = LaunchdVendorHelperGenerationObserver().observe()
    let preflightSafe = InstalledVendorXPCPreflightChecker()
      .check(generation: generation).safeToProbe
    let profileSource: ProductProfileSource =
      (try? InstalledConfigDiscovery.discoverCurrentMachine()) == nil
      ? .unavailable : .sealedInstalledConfiguration
    return ProductReadinessObservation(
      installedVersion: installation.appVersion,
      installedBuild: installation.appBuild,
      installedArchitectures: installation.appArchitectures,
      officialGUIRunning: installation.appRunning,
      helperAvailable: helperArtifactAvailable(),
      generation: generation,
      directXPCStatus: .notProbed,
      directXPCPreflightSafe: preflightSafe,
      profileSource: profileSource,
      resourceSource: .unavailable,
      resourceCandidates: []
    )
  }

  private func helperArtifactAvailable() -> Bool {
    var metadata = stat()
    guard Self.helperPath.withCString({ lstat($0, &metadata) }) == 0 else {
      return false
    }
    let permissions = metadata.st_mode
    return permissions & S_IFMT == S_IFREG
      && metadata.st_uid == 0
      && permissions & S_IXUSR != 0
      && permissions & (S_IWGRP | S_IWOTH) == 0
  }
}

public struct ProductReadinessRuntime: Sendable {
  let observer: any ProductReadinessObserving

  public init(
    observer: any ProductReadinessObserving = InstalledProductReadinessObserver()
  ) {
    self.observer = observer
  }

  public func doctor() -> ProductDoctorReport {
    let observation = observer.observe()
    let snapshot = snapshotReport(observation)
    let blocker = primaryBlocker(observation, snapshot: snapshot)
    return ProductDoctorReport(
      productState: blocker == nil ? .ready : .blocked,
      installedVersion: observation.installedVersion,
      installedBuild: observation.installedBuild,
      installedArchitectures: observation.installedArchitectures,
      officialGUIRunning: observation.officialGUIRunning,
      helperAvailable: observation.helperAvailable,
      profileSource: observation.profileSource,
      resourceSource: observation.resourceSource,
      snapshotComplete: snapshot.snapshotComplete,
      firstMissingField: snapshot.firstMissingField,
      blocker: blocker
    )
  }

  public func helperStatus() -> ProductHelperStatusReport {
    let observation = observer.observe()
    let probeAvailable =
      observation.helperAvailable
      && observation.generation.launchdObserved
      && observation.directXPCPreflightSafe
    let state: ProductState
    let blocker: ProductBlocker?
    if !observation.helperAvailable {
      state = .blocked
      blocker = .helperUnavailable
    } else if !observation.generation.launchdObserved {
      state = .blocked
      blocker = .helperGenerationUnavailable
    } else if !observation.directXPCPreflightSafe {
      state = .blocked
      blocker = .directXPCPreflightUnsafe
    } else if observation.directXPCStatus == .currentReachable {
      state = .ready
      blocker = nil
    } else if observation.directXPCStatus == .currentUnreachable {
      state = .blocked
      blocker = .directXPCUnreachable
    } else {
      state = .degraded
      blocker = .directXPCNotProbed
    }
    return ProductHelperStatusReport(
      productState: state,
      helperAvailable: observation.helperAvailable,
      generation: ProductHelperGeneration(observation.generation),
      directXPCStatus: observation.directXPCStatus,
      liveProbePerformed: observation.directXPCStatus == .currentReachable
        || observation.directXPCStatus == .currentUnreachable,
      probeAvailable: probeAvailable,
      preflightSafe: observation.directXPCPreflightSafe,
      blocker: blocker
    )
  }

  public func resources() -> ProductResourcesReport {
    let observation = observer.observe()
    let resources = observation.resourceCandidates.map(\.summary)
    let validCatalog = resourceCatalogValid(observation.resourceCandidates)
    let available =
      observation.resourceSource == .authenticatedPortalSnapshot
      && validCatalog
    return ProductResourcesReport(
      productState: available ? .ready : .blocked,
      profileSource: observation.profileSource,
      resourceSource: observation.resourceSource,
      selectableResourceCount: resources.count,
      selectableResources: resources,
      blocker: available
        ? nil
        : (observation.resourceSource == .unavailable
          ? .authenticatedPortalSnapshotUnavailable : .resourceCatalogInvalid)
    )
  }

  public func snapshotDryRun() -> ProductSnapshotDryRunReport {
    snapshotReport(observer.observe())
  }

  private func snapshotReport(
    _ observation: ProductReadinessObservation
  ) -> ProductSnapshotDryRunReport {
    let catalogValid = resourceCatalogValid(observation.resourceCandidates)
    let candidate =
      observation.resourceSource == .authenticatedPortalSnapshot
        && catalogValid && observation.resourceCandidates.count == 1
      ? observation.resourceCandidates[0] : nil
    let readiness =
      candidate?.fieldReports
      ?? VendorCharonStartValidator.validate(VendorCharonStartCandidate()).fieldReports
    let fields = readiness.map { report in
      VendorSnapshotFieldReport(
        field: report.field,
        requirement: report.requirement,
        availability: report.availability,
        sources: report.sources,
        firstIssuePath: report.firstIssuePath
      )
    }
    let firstMissing =
      candidate?.firstMissingField
      ?? readiness.first { $0.availability.blocksSnapshot }?.field
    let complete =
      candidate?.snapshotComplete == true
      && observation.resourceSource == .authenticatedPortalSnapshot
      && candidate != nil
    let blocker: ProductBlocker?
    if complete {
      blocker = nil
    } else if observation.resourceSource == .unavailable {
      blocker = .authenticatedPortalSnapshotUnavailable
    } else if observation.resourceCandidates.isEmpty {
      blocker = .authenticatedPortalSnapshotUnavailable
    } else if !catalogValid {
      blocker = .resourceCatalogInvalid
    } else if observation.resourceCandidates.count != 1 {
      blocker = .resourceSelectionRequired
    } else {
      blocker = .authorizedResourceSnapshotIncomplete
    }
    return ProductSnapshotDryRunReport(
      productState: complete ? .ready : .blocked,
      profileSource: observation.profileSource,
      resourceSource: observation.resourceSource,
      selectedResource: candidate?.summary,
      fields: fields,
      snapshotComplete: complete,
      firstMissingField: firstMissing,
      blocker: blocker
    )
  }

  private func primaryBlocker(
    _ observation: ProductReadinessObservation,
    snapshot: ProductSnapshotDryRunReport
  ) -> ProductBlocker? {
    if observation.installedVersion == nil || observation.installedBuild == nil {
      return .powerVPNNotInstalled
    }
    if !observation.helperAvailable {
      return .helperUnavailable
    }
    if observation.profileSource == .unavailable {
      return .installedConfigurationUnavailable
    }
    if let blocker = snapshot.blocker {
      return blocker
    }
    if observation.officialGUIRunning {
      return .officialGUIRunning
    }
    if !observation.generation.launchdObserved {
      return .helperGenerationUnavailable
    }
    if !observation.directXPCPreflightSafe {
      return .directXPCPreflightUnsafe
    }
    switch observation.directXPCStatus {
    case .currentReachable: return nil
    case .currentUnreachable: return .directXPCUnreachable
    case .notProbed: return .directXPCNotProbed
    }
  }

  private func resourceCatalogValid(
    _ candidates: [ProductResourceCandidate]
  ) -> Bool {
    guard !candidates.isEmpty,
      candidates.allSatisfy({
        !$0.summary.handle.isEmpty
          && $0.summary.handle.utf8.count <= 256
          && !$0.summary.displayName.isEmpty
          && $0.summary.displayName.utf8.count <= 256
      })
    else { return false }
    return Set(candidates.map(\.summary.handle)).count == candidates.count
  }
}
