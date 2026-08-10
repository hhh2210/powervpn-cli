import PowerVPNCore

package struct ProductM2ConnectOnceDependencies: Sendable {
  package let controlRuntimePreflightAccepted: @Sendable () -> Bool
  package let observeGeneration: @Sendable () -> VendorHelperGenerationSnapshot
  package let preflightAccepted: @Sendable (VendorHelperGenerationSnapshot) -> Bool
  package let captureNetworkBaseline: @Sendable () async -> ProductM2NetworkBaseline?
  package let baselineStable: @Sendable (ProductM2NetworkBaseline, ProductM2NetworkBaseline) -> Bool
  package let acquirePortal: @Sendable () async -> ProductM2PortalAcquisition
  package let control: ProductM2ControlAdapter
  package let proveFreshSSH: @Sendable (ProductM2SSHTarget) async -> ProductM2SSHProofOutcome
  package let verifyCleanup: @Sendable (ProductM2NetworkBaseline) async -> ProductM2CleanupEvidence

  package init(
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool,
    observeGeneration: @escaping @Sendable () -> VendorHelperGenerationSnapshot,
    preflightAccepted:
      @escaping @Sendable (
        VendorHelperGenerationSnapshot
      ) -> Bool,
    captureNetworkBaseline: @escaping @Sendable () async -> ProductM2NetworkBaseline?,
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
      ) async -> ProductM2SSHProofOutcome,
    verifyCleanup:
      @escaping @Sendable (
        ProductM2NetworkBaseline
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
}
