import PowerVPNCore

extension ProductPersistentTunnelCoordinator {
  func replyValidator(
    before: VendorHelperGenerationSnapshot,
    deadline: ProductM2StageDeadline
  ) -> @Sendable () async -> Bool {
    let observe = dependencies.observeGeneration
    return {
      ProductM2GenerationFence.validatesReply(
        before: before,
        current: await observe(deadline)
      )
    }
  }

  func applyWorkAbortIfNeeded(
    _ execution: inout ProductM2Execution,
    budget: ProductM2AbsoluteBudget
  ) -> Bool {
    if !budget.work.hasRemaining {
      execution.fail(
        .deadlineExceeded,
        event: .deadlineExceeded,
        state: execution.helperMutationRequested ? .failed : .blocked
      )
      return true
    }
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return true
    }
    return false
  }

  func shutdown(
    _ assets: ProductPersistentTunnelSessionAssets,
    deadlines: ProductM2CleanupDeadlines
  ) async -> ProductM2CleanupResult {
    let cleanup = await ProductM2CleanupRunner(dependencies: dependencies).run(
      baseline: assets.baseline,
      networkWindow: assets.execution.networkWindow,
      coldGeneration: assets.coldGeneration,
      authorizationLease: assets.authorizationLease,
      selectedRoutes: assets.selectedRoutes,
      controlAuthority: assets.controlAuthority,
      deadlines: deadlines
    )
    withExtendedLifetime(assets.mutationLease) {}
    return cleanup
  }

  func connectOnceReport(
    _ execution: inout ProductM2Execution,
    cleanup: ProductM2CleanupResult,
    reportDeadline: ProductM2StageDeadline
  ) -> ProductM2ConnectReport {
    execution.apply(cleanup)
    if execution.outcome != .cleanupUnproven, !reportDeadline.hasRemaining {
      execution.fail(
        .deadlineExceeded,
        event: .deadlineExceeded,
        state: execution.helperMutationRequested ? .disconnected : .blocked
      )
    }
    return execution.report()
  }

  func finishOpenFailure(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease? = nil,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil,
    start: ProductM2StartResult? = nil,
    mutationLease: any ProductMutationLeaseHolding,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelSessionOpenResult {
    let report = await finish(
      &execution,
      baseline: baseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selectedRoutes,
      controlAuthority: ProductM2ControlCleanupAuthority(
        lease: start?.lease,
        provisionalStop: start?.provisionalStopCapability,
        emergencyStop: start?.emergencyStopCapability,
        routeActivation: execution.routeActivation,
        startReceipt: start?.receipt ?? .unsent(.notAttempted)
      ),
      mutationLease: mutationLease,
      deadlines: ProductM2CleanupDeadlines(budget),
      reportDeadline: budget.report
    )
    return .failed(report)
  }

  func finish(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease? = nil,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil,
    controlAuthority: ProductM2ControlCleanupAuthority,
    mutationLease: any ProductMutationLeaseHolding,
    deadlines: ProductM2CleanupDeadlines,
    reportDeadline: ProductM2StageDeadline?
  ) async -> ProductM2ConnectReport {
    let cleanup = await ProductM2CleanupRunner(dependencies: dependencies).run(
      baseline: baseline,
      networkWindow: execution.networkWindow,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selectedRoutes,
      controlAuthority: controlAuthority,
      deadlines: deadlines
    )
    withExtendedLifetime(mutationLease) {}
    execution.apply(cleanup)
    if execution.outcome != .cleanupUnproven,
      let reportDeadline,
      !reportDeadline.hasRemaining
    {
      execution.fail(
        .deadlineExceeded,
        event: .deadlineExceeded,
        state: execution.helperMutationRequested ? .disconnected : .blocked
      )
    }
    return execution.report()
  }

  func finishStartFailure(
    _ execution: inout ProductM2Execution,
    _ baseline: ProductM2NetworkBaseline,
    _ coldGeneration: VendorHelperGenerationSnapshot,
    _ authorizationLease: ProductM2AuthorizedResourceLease?,
    _ selection: ProductM2AuthorizedResourceSelection,
    _ mutationLease: any ProductMutationLeaseHolding,
    _ start: ProductM2StartResult?,
    _ budget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelSessionOpenResult {
    await finishOpenFailure(
      &execution,
      baseline: baseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selection.selectedRoutes,
      start: start,
      mutationLease: mutationLease,
      budget: budget
    )
  }
}
