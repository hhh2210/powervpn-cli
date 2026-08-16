import PowerVPNCore

extension ProductPersistentTunnelCoordinator {
  func selectPrepareAndOpen(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease,
    mutationLease: any ProductMutationLeaseHolding,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelSessionOpenResult {
    let selection: ProductM2AuthorizedResourceSelection
    do {
      selection = try await authorizationLease.selectUnique(
        displayName: execution.request.resourceDisplayName,
        requiredTargetIPv4: execution.request.sshTarget.requiredTargetIPv4
      )
    } catch {
      applySelectionFailure(error, to: &execution)
      return await finishOpenFailure(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        mutationLease: mutationLease,
        budget: budget
      )
    }

    execution.lastGoodState = .ready
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishOpenFailure(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        mutationLease: mutationLease,
        budget: budget
      )
    }

    guard
      let preStartBaseline = await dependencies.captureNetworkBaseline(
        execution.networkWindow,
        selection.selectedRoutes,
        budget.work
      ).baseline
    else {
      if !applyWorkAbortIfNeeded(&execution, budget: budget) {
        execution.fail(
          .networkBaselineUnavailable,
          event: .networkBaselineUnavailable,
          state: .blocked
        )
      }
      return await finishOpenFailure(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selection.selectedRoutes,
        mutationLease: mutationLease,
        budget: budget
      )
    }

    guard
      await validatePreStart(
        &execution,
        originalBaseline: baseline,
        preStartBaseline: preStartBaseline,
        coldGeneration: coldGeneration,
        budget: budget
      )
    else {
      return await finishOpenFailure(
        &execution,
        baseline: preStartBaseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selection.selectedRoutes,
        mutationLease: mutationLease,
        budget: budget
      )
    }

    return await startAndOpen(
      &execution,
      baseline: preStartBaseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selection: selection,
      mutationLease: mutationLease,
      budget: budget
    )
  }

  private func validatePreStart(
    _ execution: inout ProductM2Execution,
    originalBaseline: ProductM2NetworkBaseline,
    preStartBaseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    budget: ProductM2AbsoluteBudget
  ) async -> Bool {
    if applyWorkAbortIfNeeded(&execution, budget: budget) { return false }
    guard dependencies.baselineStable(originalBaseline, preStartBaseline) else {
      execution.fail(
        .networkBaselineChanged,
        event: .networkBaselineChanged,
        state: .blocked
      )
      return false
    }

    let recheckedGeneration = await dependencies.observeGeneration(budget.work)
    if applyWorkAbortIfNeeded(&execution, budget: budget) { return false }
    guard ProductM2GenerationFence.sameColdGeneration(coldGeneration, recheckedGeneration)
    else {
      execution.fail(
        .generationFenceRejected,
        event: .generationFenceRejected,
        state: .blocked
      )
      return false
    }

    let accepted = await dependencies.preflightAccepted(recheckedGeneration, budget.work)
    if applyWorkAbortIfNeeded(&execution, budget: budget) { return false }
    guard accepted else {
      execution.fail(
        .generationFenceRejected,
        event: .generationFenceRejected,
        state: .blocked
      )
      return false
    }
    return true
  }

  private func applySelectionFailure(
    _ error: Error,
    to execution: inout ProductM2Execution
  ) {
    execution.applySelectionFailure(error)
  }
}
