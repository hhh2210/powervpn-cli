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
      if let retry = await retryCatalogAcquisitionIfEligible(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        failedLease: authorizationLease,
        mutationLease: mutationLease,
        budget: budget
      ) {
        return retry
      }
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

  private func retryCatalogAcquisitionIfEligible(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    failedLease: ProductM2AuthorizedResourceLease,
    mutationLease: any ProductMutationLeaseHolding,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelSessionOpenResult? {
    guard execution.catalogRetryEligible,
      !Task.isCancelled,
      budget.authorization.canStartFullAcquisition
    else { return nil }

    let firstClose = await Task.detached {
      await failedLease.closeAndErase(deadline: budget.authorization.cleanup)
    }.value
    execution.authorizationClose = firstClose.outcome
    execution.authorizationOwnedMaterialErased = firstClose.ownedMaterialErased
    execution.serverContactRequested =
      execution.serverContactRequested || firstClose.serverContactRequested
    guard firstClose.outcome == .accepted, firstClose.ownedMaterialErased else {
      return await finishOpenFailure(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        mutationLease: mutationLease,
        budget: budget
      )
    }
    guard !Task.isCancelled, budget.authorization.canStartFullAcquisition else {
      _ = applyWorkAbortIfNeeded(&execution, budget: budget)
      return await finishOpenFailure(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        mutationLease: mutationLease,
        budget: budget
      )
    }

    execution.prepareForAuthorizationRetry()
    let acquisition = await acquireAuthorization(budget: budget.authorization)
    switch acquisition {
    case .acquired(let source, let lease, let contacted):
      execution.serverContactRequested = execution.serverContactRequested || contacted
      execution.authorizationOwnedMaterialErased = false
      guard source == dependencies.authorizationSource, lease.source == source else {
        execution.authorizationAcquisition = .rejected
        execution.authorizationFailure = .sourceMismatch
        execution.fail(
          .authorizationAcquisitionRejected,
          event: .authorizationAcquisitionRejected,
          state: .blocked
        )
        return await finishOpenFailure(
          &execution,
          baseline: baseline,
          coldGeneration: coldGeneration,
          authorizationLease: lease,
          mutationLease: mutationLease,
          budget: budget
        )
      }
      execution.authorizationAcquisition = .acquired
      if applyWorkAbortIfNeeded(&execution, budget: budget) {
        return await finishOpenFailure(
          &execution,
          baseline: baseline,
          coldGeneration: coldGeneration,
          authorizationLease: lease,
          mutationLease: mutationLease,
          budget: budget
        )
      }
      return await selectPrepareAndOpen(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: lease,
        mutationLease: mutationLease,
        budget: budget
      )

    case .rejected(let source, let failure, let cleanup):
      applyRetryAcquisitionRejection(
        &execution,
        source: source,
        failure: failure,
        cleanup: cleanup,
        budget: budget.authorization
      )
      return await finishOpenFailure(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        mutationLease: mutationLease,
        budget: budget
      )
    }
  }

  private func applyRetryAcquisitionRejection(
    _ execution: inout ProductM2Execution,
    source: ProductM2AuthorizationSource,
    failure: ProductM2AuthorizationFailure,
    cleanup: ProductM2AuthorizationCloseReceipt,
    budget: ProductM2AuthorizationBudget
  ) {
    execution.serverContactRequested =
      execution.serverContactRequested || cleanup.serverContactRequested
    execution.authorizationOwnedMaterialErased = cleanup.ownedMaterialErased
    execution.authorizationClose =
      cleanup.outcome == .notRequired ? .accepted : cleanup.outcome
    let normalizedFailure =
      source == dependencies.authorizationSource ? failure : .sourceMismatch
    execution.authorizationAcquisition =
      normalizedFailure == .cancelled ? .cancelled : .rejected
    execution.authorizationFailure = normalizedFailure
    let deadlineExceeded = normalizedFailure == .timedOut || !budget.work.hasRemaining
    execution.fail(
      deadlineExceeded
        ? .deadlineExceeded
        : (normalizedFailure == .cancelled ? .cancelled : .authorizationAcquisitionRejected),
      event: deadlineExceeded
        ? .deadlineExceeded
        : (normalizedFailure == .cancelled ? .cancelled : .authorizationAcquisitionRejected),
      state: deadlineExceeded || normalizedFailure == .cancelled ? .failed : .blocked
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
