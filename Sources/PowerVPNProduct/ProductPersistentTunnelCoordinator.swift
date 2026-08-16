package struct ProductPersistentTunnelCoordinator: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies
  let captureActiveDiagnosticsBeforeOpen: Bool

  init(
    dependencies: ProductM2ConnectOnceDependencies,
    captureActiveDiagnosticsBeforeOpen: Bool = true
  ) {
    self.dependencies = dependencies
    self.captureActiveDiagnosticsBeforeOpen = captureActiveDiagnosticsBeforeOpen
  }
}

package actor ProductPersistentTunnelRuntime {
  private let session: ProductPersistentTunnelSession
  package nonisolated let authorizationAvailabilityFailure: ProductM2AuthorizationFailure?

  package init(dependencies: ProductM2ConnectOnceDependencies) {
    authorizationAvailabilityFailure = dependencies.authorizationAvailabilityFailure
    session = ProductPersistentTunnelSession(
      coordinator: ProductPersistentTunnelCoordinator(dependencies: dependencies)
    )
  }

  package func open(
    request: ProductM2ConnectRequest,
    startupBudget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelOpenResult {
    await session.open(request, startupBudget: startupBudget)
  }
}
