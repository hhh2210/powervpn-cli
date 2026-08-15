package struct ProductPersistentTunnelCoordinator: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies
}

package actor ProductPersistentTunnelRuntime {
  private let session: ProductPersistentTunnelSession

  package init(dependencies: ProductM2ConnectOnceDependencies) {
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
