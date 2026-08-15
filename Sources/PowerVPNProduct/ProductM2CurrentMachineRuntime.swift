import PowerVPNCore
import PowerVPNPortal

/// Explicit composition root for the current-machine M2 path. Construction is
/// inert; only `run` may mutate the helper, run SSH, or contact a remote service.
package struct ProductM2CurrentMachineRuntime: Sendable {
  private let coordinator: ProductM2ConnectOnceCoordinator
  package let authorizationAvailabilityFailure: ProductM2AuthorizationFailure?

  package init() {
    self.init(
      controlRuntimePreflightAccepted: ProductM2ControlAdapter.runtimePreflightAccepted,
      generationObserver: InstalledBoundedVendorHelperGenerationObserver(),
      preflightChecker: InstalledBoundedVendorXPCPreflightChecker(),
      networkObserver: InstalledNetworkCleanupObserver(),
      authorizationProvider: ProductM2PortalAdapter { _ in
        await PortalLoginRuntime.acquireCurrentMachine()
      },
      control: ProductM2ControlAdapter(),
      freshSSHProver: ProductM2FreshSSHProver()
    )
  }

  init(
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool,
    generationObserver: any BoundedVendorHelperGenerationObserving,
    preflightChecker: any BoundedVendorXPCPreflightChecking,
    networkObserver: any NetworkCleanupObserving,
    authorizationProvider: any ProductM2AuthorizedResourceProviding =
      ProductM2UnavailableNativePortalProvider(),
    control: ProductM2ControlAdapter,
    freshSSHProver: ProductM2FreshSSHProver
  ) {
    authorizationAvailabilityFailure = authorizationProvider.availabilityFailure
    coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: ProductM2ConnectOnceDependencies(
        controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
        generationObserver: generationObserver,
        preflightChecker: preflightChecker,
        networkObserver: networkObserver,
        authorizationProvider: authorizationProvider,
        control: control,
        freshSSHProver: freshSSHProver
      ))
  }

  package func run(
    _ request: ProductM2ConnectRequest,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2ConnectReport {
    await coordinator.run(request, budget: budget)
  }
}
