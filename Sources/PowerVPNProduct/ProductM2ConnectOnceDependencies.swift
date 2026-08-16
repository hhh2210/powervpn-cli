import PowerVPNCore

package struct ProductM2ConnectOnceDependencies: Sendable {
  package let acquireMutationLease: @Sendable () throws -> any ProductMutationLeaseHolding
  package let controlRuntimePreflightAccepted: @Sendable () -> Bool
  package let observeGeneration:
    @Sendable (ProductM2StageDeadline) async -> VendorHelperGenerationSnapshot
  package let preflightAccepted:
    @Sendable (VendorHelperGenerationSnapshot, ProductM2StageDeadline) async -> Bool
  package let captureNetworkBaseline:
    @Sendable (
      NetworkCleanupCaptureWindow,
      VendorCharonSelectedRouteMatcher?,
      ProductM2StageDeadline
    ) async -> ProductM2ActiveCaptureOutcome
  package let baselineStable: @Sendable (ProductM2NetworkBaseline, ProductM2NetworkBaseline) -> Bool
  package let assessActiveConnection:
    @Sendable (
      ProductM2NetworkBaseline,
      ProductM2NetworkBaseline
    ) -> ProductM2ActiveNetworkEvidence
  package let authorizationSource: ProductM2AuthorizationSource
  package let authorizationAvailabilityFailure: ProductM2AuthorizationFailure?
  package let beginAuthorization:
    @Sendable (ProductM2AuthorizationBudget) -> ProductM2AuthorizationAttempt
  package let control: ProductM2ControlAdapter
  package let proveFreshSSH:
    @Sendable (
      ProductM2SSHTarget,
      ProductM2StageDeadline
    ) async -> ProductM2FreshSSHProofEvidence
  package let verifyCleanup:
    @Sendable (
      ProductM2NetworkBaseline,
      NetworkCleanupCaptureWindow,
      VendorCharonSelectedRouteMatcher?,
      Bool,
      ProductM2StageDeadline
    ) async -> ProductM2CleanupEvidence

  package init(
    acquireMutationLease:
      @escaping @Sendable () throws -> any ProductMutationLeaseHolding,
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool,
    observeGeneration:
      @escaping @Sendable (
        ProductM2StageDeadline
      ) async -> VendorHelperGenerationSnapshot,
    preflightAccepted:
      @escaping @Sendable (
        VendorHelperGenerationSnapshot,
        ProductM2StageDeadline
      ) async -> Bool,
    captureNetworkBaseline:
      @escaping @Sendable (
        NetworkCleanupCaptureWindow,
        VendorCharonSelectedRouteMatcher?,
        ProductM2StageDeadline
      ) async -> ProductM2ActiveCaptureOutcome,
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
    beginAuthorization:
      @escaping @Sendable (
        ProductM2AuthorizationBudget
      ) -> ProductM2AuthorizationAttempt,
    control: ProductM2ControlAdapter,
    proveFreshSSH:
      @escaping @Sendable (
        ProductM2SSHTarget,
        ProductM2StageDeadline
      ) async -> ProductM2FreshSSHProofEvidence,
    verifyCleanup:
      @escaping @Sendable (
        ProductM2NetworkBaseline,
        NetworkCleanupCaptureWindow,
        VendorCharonSelectedRouteMatcher?,
        Bool,
        ProductM2StageDeadline
      ) async -> ProductM2CleanupEvidence
  ) {
    self.acquireMutationLease = acquireMutationLease
    self.controlRuntimePreflightAccepted = controlRuntimePreflightAccepted
    self.observeGeneration = observeGeneration
    self.preflightAccepted = preflightAccepted
    self.captureNetworkBaseline = captureNetworkBaseline
    self.baselineStable = baselineStable
    self.assessActiveConnection = assessActiveConnection
    self.authorizationSource = authorizationSource
    self.authorizationAvailabilityFailure = authorizationAvailabilityFailure
    self.beginAuthorization = beginAuthorization
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
      acquireMutationLease: ProductMutationLease.acquireCurrentMachine,
      controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
      observeGeneration: { deadline in
        guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
          return .unavailable
        }
        return await generationObserver.observe(timeoutMilliseconds: timeout)
      },
      preflightAccepted: { generation, deadline in
        guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
          return false
        }
        return await preflightChecker.check(
          generation: generation,
          timeoutMilliseconds: timeout
        ).safeToProbe
      },
      captureNetworkBaseline: { window, selectedRoutes, deadline in
        let snapshot = await networkObserver.capture(
          window: window,
          selectedRoutes: selectedRoutes,
          timeoutMilliseconds: deadline.remainingMilliseconds(cappedAt: 24_000) ?? 0
        )
        return ProductM2ActiveCaptureOutcome(snapshot: snapshot)
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
      beginAuthorization: authorizationProvider.beginAcquire,
      control: control,
      proveFreshSSH: { target, deadline in
        guard let timeout = deadline.remainingMilliseconds(cappedAt: 15_000) else {
          return ProductM2FreshSSHProofEvidence.timedOut(target: target)
        }
        return await freshSSHProver.prove(target, timeoutMilliseconds: timeout)
      },
      verifyCleanup: { baseline, window, selectedRoutes, startRequestSent, deadline in
        guard let before = baseline.snapshot else { return .unavailable }
        let after = await networkObserver.capture(
          window: window,
          selectedRoutes: selectedRoutes,
          timeoutMilliseconds: deadline.remainingMilliseconds(cappedAt: 24_000) ?? 0
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
