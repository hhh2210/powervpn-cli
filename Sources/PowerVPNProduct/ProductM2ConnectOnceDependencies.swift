import PowerVPNCore

package struct ProductM2ConnectOnceDependencies: Sendable {
  package let controlRuntimePreflightAccepted: @Sendable () -> Bool
  package let observeGeneration: @Sendable () async -> VendorHelperGenerationSnapshot
  package let preflightAccepted: @Sendable (VendorHelperGenerationSnapshot) -> Bool
  package let captureNetworkBaseline:
    @Sendable (
      NetworkCleanupCaptureWindow,
      VendorCharonSelectedRouteMatcher?
    ) async -> ProductM2NetworkBaseline?
  package let baselineStable: @Sendable (ProductM2NetworkBaseline, ProductM2NetworkBaseline) -> Bool
  package let acquirePortal: @Sendable () async -> ProductM2PortalAcquisition
  package let control: ProductM2ControlAdapter
  package let proveFreshSSH: @Sendable (ProductM2SSHTarget) async -> ProductM2FreshSSHProofEvidence
  package let verifyCleanup:
    @Sendable (
      ProductM2NetworkBaseline,
      NetworkCleanupCaptureWindow,
      VendorCharonSelectedRouteMatcher?,
      Bool
    ) async -> ProductM2CleanupEvidence

  package init(
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool,
    observeGeneration: @escaping @Sendable () async -> VendorHelperGenerationSnapshot,
    preflightAccepted:
      @escaping @Sendable (
        VendorHelperGenerationSnapshot
      ) -> Bool,
    captureNetworkBaseline:
      @escaping @Sendable (
        NetworkCleanupCaptureWindow,
        VendorCharonSelectedRouteMatcher?
      ) async -> ProductM2NetworkBaseline?,
    baselineStable:
      @escaping @Sendable (
        ProductM2NetworkBaseline,
        ProductM2NetworkBaseline
      ) -> Bool,
    acquirePortal: @escaping @Sendable () async -> ProductM2PortalAcquisition,
    control: ProductM2ControlAdapter,
    proveFreshSSH:
      @escaping @Sendable (
        ProductM2SSHTarget
      ) async -> ProductM2FreshSSHProofEvidence,
    verifyCleanup:
      @escaping @Sendable (
        ProductM2NetworkBaseline,
        NetworkCleanupCaptureWindow,
        VendorCharonSelectedRouteMatcher?,
        Bool
      ) async -> ProductM2CleanupEvidence
  ) {
    self.controlRuntimePreflightAccepted = controlRuntimePreflightAccepted
    self.observeGeneration = observeGeneration
    self.preflightAccepted = preflightAccepted
    self.captureNetworkBaseline = captureNetworkBaseline
    self.baselineStable = baselineStable
    self.acquirePortal = acquirePortal
    self.control = control
    self.proveFreshSSH = proveFreshSSH
    self.verifyCleanup = verifyCleanup
  }

  /// Production adapter. Callers must explicitly supply the current-machine
  /// observer/prover; constructing generic synthetic dependencies never runs
  /// commands, SSH, Portal, or XPC.
  package init(
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool,
    generationObserver: any BoundedVendorHelperGenerationObserving,
    preflightAccepted:
      @escaping @Sendable (VendorHelperGenerationSnapshot) -> Bool,
    networkObserver: any NetworkCleanupObserving,
    acquirePortal: @escaping @Sendable () async -> ProductM2PortalAcquisition,
    control: ProductM2ControlAdapter,
    freshSSHProver: ProductM2FreshSSHProver
  ) {
    self.init(
      controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
      observeGeneration: generationObserver.observe,
      preflightAccepted: preflightAccepted,
      captureNetworkBaseline: { window, selectedRoutes in
        let snapshot = await networkObserver.capture(
          window: window,
          selectedRoutes: selectedRoutes
        )
        return snapshot.complete ? ProductM2NetworkBaseline(snapshot: snapshot) : nil
      },
      baselineStable: ProductM2NetworkBaseline.stable,
      acquirePortal: acquirePortal,
      control: control,
      proveFreshSSH: freshSSHProver.prove,
      verifyCleanup: { baseline, window, selectedRoutes, startRequestSent in
        guard let before = baseline.snapshot else { return .unavailable }
        let after = await networkObserver.capture(
          window: window,
          selectedRoutes: selectedRoutes
        )
        return ProductM2CleanupEvidence(
          NetworkCleanupAssessment.assess(
            before: before,
            after: after,
            startRequestSent: startRequestSent
          ))
      }
    )
  }
}
