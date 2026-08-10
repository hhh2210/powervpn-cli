import PowerVPNPortal

extension ProductReadinessRuntime {
  /// Produces a value-free resource report from one already-authenticated,
  /// generation-bound Portal snapshot. It performs no network or helper call.
  package func resources(
    from snapshot: AuthenticatedPortalSnapshot
  ) throws -> ProductResourcesReport {
    ProductReadinessRuntime(
      observer: FixedProductReadinessObservation(
        try observation(from: snapshot)
      )
    ).resources()
  }

  /// Runs the Core charon contract against one authenticated resource tree.
  /// Snapshot values remain borrowed and are never serialized into the report.
  package func snapshotDryRun(
    from snapshot: AuthenticatedPortalSnapshot
  ) throws -> ProductSnapshotDryRunReport {
    ProductReadinessRuntime(
      observer: FixedProductReadinessObservation(
        try observation(from: snapshot)
      )
    ).snapshotDryRun()
  }

  private func observation(
    from snapshot: AuthenticatedPortalSnapshot
  ) throws -> ProductReadinessObservation {
    let current = observer.observe()
    return ProductReadinessObservation(
      installedVersion: current.installedVersion,
      installedBuild: current.installedBuild,
      installedArchitectures: current.installedArchitectures,
      officialGUIRunning: current.officialGUIRunning,
      helperAvailable: current.helperAvailable,
      generation: current.generation,
      directXPCStatus: current.directXPCStatus,
      directXPCPreflightSafe: current.directXPCPreflightSafe,
      profileSource: current.profileSource,
      resourceSource: .authenticatedPortalSnapshot,
      resourceCandidates: try AuthenticatedPortalSnapshotMapper.map(snapshot)
    )
  }
}

private struct FixedProductReadinessObservation: ProductReadinessObserving {
  let value: ProductReadinessObservation

  init(_ value: ProductReadinessObservation) {
    self.value = value
  }

  func observe() -> ProductReadinessObservation { value }
}
