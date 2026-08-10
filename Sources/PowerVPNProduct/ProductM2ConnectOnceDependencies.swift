import PowerVPNCore

package struct ProductM2ConnectOnceDependencies: Sendable {
  package let controlRuntimePreflightAccepted: @Sendable () -> Bool
  package let observeGeneration: @Sendable () async -> VendorHelperGenerationSnapshot
  package let preflightAccepted: @Sendable (VendorHelperGenerationSnapshot) async -> Bool
  package let captureNetworkBaseline:
    @Sendable (
      NetworkCleanupCaptureWindow,
      VendorCharonSelectedRouteMatcher?
    ) async -> ProductM2NetworkBaseline?
  package let baselineStable: @Sendable (ProductM2NetworkBaseline, ProductM2NetworkBaseline) -> Bool
  package let assessActiveConnection:
    @Sendable (
      ProductM2NetworkBaseline,
      ProductM2NetworkBaseline
    ) -> ProductM2ActiveNetworkEvidence
  package let authorizationSource: ProductM2AuthorizationSource
  package let authorizationAvailabilityFailure: ProductM2AuthorizationFailure?
  package let acquireAuthorization: @Sendable () async -> ProductM2AuthorizedResourceAcquisition
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
      ) async -> Bool,
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
    assessActiveConnection:
      @escaping @Sendable (
        ProductM2NetworkBaseline,
        ProductM2NetworkBaseline
      ) -> ProductM2ActiveNetworkEvidence,
    authorizationSource: ProductM2AuthorizationSource = .nativePortal,
    authorizationAvailabilityFailure: ProductM2AuthorizationFailure? = nil,
    acquireAuthorization:
      @escaping @Sendable () async -> ProductM2AuthorizedResourceAcquisition,
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
    self.assessActiveConnection = assessActiveConnection
    self.authorizationSource = authorizationSource
    self.authorizationAvailabilityFailure = authorizationAvailabilityFailure
    self.acquireAuthorization = acquireAuthorization
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
    preflightChecker: any BoundedVendorXPCPreflightChecking,
    networkObserver: any NetworkCleanupObserving,
    authorizationProvider: any ProductM2AuthorizedResourceProviding,
    control: ProductM2ControlAdapter,
    freshSSHProver: ProductM2FreshSSHProver
  ) {
    self.init(
      controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
      observeGeneration: generationObserver.observe,
      preflightAccepted: { generation in
        await preflightChecker.check(generation: generation).safeToProbe
      },
      captureNetworkBaseline: { window, selectedRoutes in
        let snapshot = await networkObserver.capture(
          window: window,
          selectedRoutes: selectedRoutes
        )
        return snapshot.complete ? ProductM2NetworkBaseline(snapshot: snapshot) : nil
      },
      baselineStable: ProductM2NetworkBaseline.stable,
      assessActiveConnection: { before, active in
        guard let before = before.snapshot, let active = active.snapshot else {
          return .unavailable
        }
        return ProductM2ActiveNetworkEvidence(
          NetworkConnectionAssessment.assess(before: before, active: active)
        )
      },
      authorizationSource: authorizationProvider.source,
      authorizationAvailabilityFailure: authorizationProvider.availabilityFailure,
      acquireAuthorization: authorizationProvider.acquire,
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
