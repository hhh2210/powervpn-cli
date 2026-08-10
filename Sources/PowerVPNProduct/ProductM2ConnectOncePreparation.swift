import PowerVPNCore

extension ProductM2ConnectOnceCoordinator {
  func selectPrepareAndRun(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2ConnectReport {
    let selection: ProductM2AuthorizedResourceSelection
    do {
      selection = try await authorizationLease.selectUnique(
        displayName: execution.request.resourceDisplayName,
        requiredTargetIPv4: execution.request.sshTarget.requiredTargetIPv4
      )
    } catch ProductM2AuthorizedResourceSelectionError.resourceNotFound {
      execution.fail(.resourceNotFound, event: .resourceNotFound, state: .blocked)
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    } catch ProductM2AuthorizedResourceSelectionError.resourceAmbiguous {
      execution.fail(.resourceAmbiguous, event: .resourceAmbiguous, state: .blocked)
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    } catch ProductM2AuthorizedResourceSelectionError.selectedRouteCoverageRejected {
      execution.fail(
        .selectedRouteCoverageRejected,
        event: .selectedRouteCoverageRejected,
        state: .blocked
      )
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    } catch ProductM2AuthorizedResourceSelectionError.startSnapshotRejected {
      execution.fail(
        .startSnapshotRejected,
        event: .startSnapshotRejected,
        state: .blocked
      )
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    } catch {
      execution.fail(
        .resourceCatalogRejected,
        event: .resourceCatalogRejected,
        state: .blocked
      )
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    }

    execution.lastGoodState = .ready
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    }

    let selectedRoutes = selection.selectedRoutes
    guard
      let preStartBaseline = await dependencies.captureNetworkBaseline(
        execution.networkWindow,
        selectedRoutes,
        budget.work
      )
    else {
      if applyWorkAbortIfNeeded(&execution, budget: budget) {
        return await finishPreparation(
          &execution, baseline, coldGeneration, authorizationLease, budget)
      }
      execution.fail(
        .networkBaselineUnavailable,
        event: .networkBaselineUnavailable,
        state: .blocked
      )
      return await finishPreparation(
        &execution, baseline, coldGeneration, authorizationLease, budget)
    }
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishPreparation(
        &execution,
        preStartBaseline,
        coldGeneration,
        authorizationLease,
        budget,
        selectedRoutes
      )
    }
    guard dependencies.baselineStable(baseline, preStartBaseline) else {
      execution.fail(
        .networkBaselineChanged,
        event: .networkBaselineChanged,
        state: .blocked
      )
      return await finishPreparation(
        &execution,
        preStartBaseline,
        coldGeneration,
        authorizationLease,
        budget,
        selectedRoutes
      )
    }

    let recheckedGeneration = await dependencies.observeGeneration(budget.work)
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishPreparation(
        &execution,
        preStartBaseline,
        coldGeneration,
        authorizationLease,
        budget,
        selectedRoutes
      )
    }
    guard ProductM2GenerationFence.sameColdGeneration(coldGeneration, recheckedGeneration) else {
      execution.fail(
        .generationFenceRejected,
        event: .generationFenceRejected,
        state: .blocked
      )
      return await finishPreparation(
        &execution,
        preStartBaseline,
        coldGeneration,
        authorizationLease,
        budget,
        selectedRoutes
      )
    }

    let recheckedPreflight = await dependencies.preflightAccepted(
      recheckedGeneration,
      budget.work
    )
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishPreparation(
        &execution,
        preStartBaseline,
        coldGeneration,
        authorizationLease,
        budget,
        selectedRoutes
      )
    }
    guard recheckedPreflight else {
      execution.fail(
        .generationFenceRejected,
        event: .generationFenceRejected,
        state: .blocked
      )
      return await finishPreparation(
        &execution,
        preStartBaseline,
        coldGeneration,
        authorizationLease,
        budget,
        selectedRoutes
      )
    }

    return await startProveAndFinish(
      &execution,
      baseline: preStartBaseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selection: selection,
      budget: budget
    )
  }

  private func finishPreparation(
    _ execution: inout ProductM2Execution,
    _ baseline: ProductM2NetworkBaseline,
    _ coldGeneration: VendorHelperGenerationSnapshot,
    _ authorizationLease: ProductM2AuthorizedResourceLease,
    _ budget: ProductM2AbsoluteBudget,
    _ selectedRoutes: VendorCharonSelectedRouteMatcher? = nil
  ) async -> ProductM2ConnectReport {
    await finish(
      &execution,
      baseline: baseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selectedRoutes,
      budget: budget
    )
  }
}
