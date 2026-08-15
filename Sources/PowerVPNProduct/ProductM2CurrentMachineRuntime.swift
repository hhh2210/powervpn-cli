import PowerVPNCore
import PowerVPNPortal

/// Explicit composition root for the current-machine M2 path. Construction is
/// inert; only `run` may mutate the helper, run SSH, or contact a remote service.
package struct ProductM2CurrentMachineRuntime: Sendable {
  private let coordinator: ProductM2ConnectOnceCoordinator
  package let authorizationAvailabilityFailure: ProductM2AuthorizationFailure?

  package init() {
    let authorizationProvider = ProductM2PortalAdapter { _ in
      await PortalLoginRuntime.acquireCurrentMachine()
    }
    self.init(
      authorizationProvider: authorizationProvider,
      dependencies: ProductM2CurrentMachineComposition.dependencies(
        authorizationProvider: authorizationProvider
      )
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
    self.init(
      authorizationProvider: authorizationProvider,
      dependencies: ProductM2CurrentMachineComposition.dependencies(
        controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
        generationObserver: generationObserver,
        preflightChecker: preflightChecker,
        networkObserver: networkObserver,
        authorizationProvider: authorizationProvider,
        control: control,
        freshSSHProver: freshSSHProver
      )
    )
  }

  private init(
    authorizationProvider: any ProductM2AuthorizedResourceProviding,
    dependencies: ProductM2ConnectOnceDependencies
  ) {
    authorizationAvailabilityFailure = authorizationProvider.availabilityFailure
    coordinator = ProductM2ConnectOnceCoordinator(dependencies: dependencies)
  }

  package func run(
    _ request: ProductM2ConnectRequest,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2ConnectReport {
    await coordinator.run(request, budget: budget)
  }
}

extension ProductPersistentTunnelRuntime {
  package init() {
    let authorizationProvider = ProductM2PortalAdapter { _ in
      await PortalLoginRuntime.acquireCurrentMachine()
    }
    self.init(
      dependencies: ProductM2CurrentMachineComposition.dependencies(
        authorizationProvider: authorizationProvider
      )
    )
  }
}

private enum ProductM2CurrentMachineComposition {
  static func dependencies(
    controlRuntimePreflightAccepted: @escaping @Sendable () -> Bool =
      ProductM2ControlAdapter.runtimePreflightAccepted,
    generationObserver: any BoundedVendorHelperGenerationObserving =
      InstalledBoundedVendorHelperGenerationObserver(),
    preflightChecker: any BoundedVendorXPCPreflightChecking =
      InstalledBoundedVendorXPCPreflightChecker(),
    networkObserver: any NetworkCleanupObserving = InstalledNetworkCleanupObserver(),
    authorizationProvider: any ProductM2AuthorizedResourceProviding,
    control: ProductM2ControlAdapter = ProductM2ControlAdapter(),
    freshSSHProver: ProductM2FreshSSHProver = ProductM2FreshSSHProver()
  ) -> ProductM2ConnectOnceDependencies {
    ProductM2ConnectOnceDependencies(
      controlRuntimePreflightAccepted: controlRuntimePreflightAccepted,
      generationObserver: generationObserver,
      preflightChecker: preflightChecker,
      networkObserver: networkObserver,
      authorizationProvider: authorizationProvider,
      control: control,
      freshSSHProver: freshSSHProver
    )
  }
}
