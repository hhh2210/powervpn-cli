import PowerVPNCore

extension ProductM2ConnectOnceCoordinator {
  func replyValidator(
    before: VendorHelperGenerationSnapshot
  ) -> @Sendable () async -> Bool {
    let observe = dependencies.observeGeneration
    return {
      ProductM2GenerationFence.validatesReply(
        before: before,
        current: await observe()
      )
    }
  }

  func finish(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease? = nil,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil,
    controlLease: ProductM2ControlLease? = nil,
    startReceipt: ProductM2ControlReceipt = .unsent(.notAttempted)
  ) async -> ProductM2ConnectReport {
    let cleanup = await ProductM2CleanupRunner(dependencies: dependencies).run(
      baseline: baseline,
      networkWindow: execution.networkWindow,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selectedRoutes,
      controlLease: controlLease,
      startReceipt: startReceipt
    )
    execution.apply(cleanup)
    return execution.report()
  }
}
