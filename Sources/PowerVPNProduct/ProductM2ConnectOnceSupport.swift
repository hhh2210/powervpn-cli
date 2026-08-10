import PowerVPNCore

extension ProductM2ConnectOnceCoordinator {
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

  func finish(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease? = nil,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil,
    controlLease: ProductM2ControlLease? = nil,
    provisionalStopCapability: ProductM2ProvisionalStopCapability? = nil,
    startReceipt: ProductM2ControlReceipt = .unsent(.notAttempted),
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2ConnectReport {
    let cleanup = await ProductM2CleanupRunner(dependencies: dependencies).run(
      baseline: baseline,
      networkWindow: execution.networkWindow,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selectedRoutes,
      controlLease: controlLease,
      provisionalStopCapability: provisionalStopCapability,
      startReceipt: startReceipt,
      budget: budget
    )
    execution.apply(cleanup)
    if execution.outcome != .cleanupUnproven, !budget.report.hasRemaining {
      execution.fail(
        .deadlineExceeded,
        event: .deadlineExceeded,
        state: execution.helperMutationRequested ? .disconnected : .blocked
      )
    }
    return execution.report()
  }
}
