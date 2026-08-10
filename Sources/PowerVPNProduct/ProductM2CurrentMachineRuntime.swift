import PowerVPNCore

/// Explicit composition root for the current-machine M2 path. Construction is
/// inert; only `run` may trigger TTY, Portal, bounded inspection, SSH, or XPC.
package struct ProductM2CurrentMachineRuntime: Sendable {
  private let coordinator: ProductM2ConnectOnceCoordinator

  package init() {
    self.init(
      controlRuntimePreflightAccepted: ProductM2ControlAdapter.runtimePreflightAccepted,
      generationObserver: InstalledBoundedVendorHelperGenerationObserver(),
      preflightChecker: InstalledBoundedVendorXPCPreflightChecker(),
      networkObserver: InstalledNetworkCleanupObserver(),
      acquirePortal: ProductM2PortalAdapter.acquireCurrentMachine,
      control: ProductM2ControlAdapter(),
      freshSSHProver: ProductM2FreshSSHProver()
    )
  }

  init(
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool,
    generationObserver: any BoundedVendorHelperGenerationObserving,
    preflightChecker: any BoundedVendorXPCPreflightChecking,
    networkObserver: any NetworkCleanupObserving,
    acquirePortal: @escaping @Sendable () async -> ProductM2PortalAcquisition,
    control: ProductM2ControlAdapter,
    freshSSHProver: ProductM2FreshSSHProver
  ) {
    coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: ProductM2ConnectOnceDependencies(
        controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
        generationObserver: generationObserver,
        preflightChecker: preflightChecker,
        networkObserver: networkObserver,
        acquirePortal: acquirePortal,
        control: control,
        freshSSHProver: freshSSHProver
      ))
  }

  package func run(
    _ request: ProductM2ConnectRequest
  ) async -> ProductM2ConnectReport {
    await coordinator.run(request)
  }
}
