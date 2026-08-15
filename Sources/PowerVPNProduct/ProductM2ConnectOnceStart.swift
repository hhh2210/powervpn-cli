import PowerVPNCore

extension ProductM2ConnectOnceCoordinator {
  func startProveAndFinish(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease,
    selection: ProductM2AuthorizedResourceSelection,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2ConnectReport {
    guard budget.work.hasRemaining else {
      _ = applyWorkAbortIfNeeded(&execution, budget: budget)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selection.selectedRoutes,
        budget: budget
      )
    }
    let validator = replyValidator(before: coldGeneration, deadline: budget.work)
    let pending: ProductM2PendingStart
    do {
      pending = try await selection.beginStart(
        control: dependencies.control,
        deadline: budget.work,
        peerGenerationValidator: validator
      )
    } catch ProductM2AuthorizedResourceSelectionError.workAborted {
      if !applyWorkAbortIfNeeded(&execution, budget: budget) {
        execution.fail(
          .startSnapshotRejected,
          event: .startSnapshotRejected,
          state: .blocked
        )
      }
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selection.selectedRoutes,
        budget: budget
      )
    } catch {
      execution.fail(
        .startSnapshotRejected,
        event: .startSnapshotRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selection.selectedRoutes,
        budget: budget
      )
    }

    execution.lastGoodState = .connecting
    let start =
      await pending.result()
    execution.startOutcome = start.receipt.outcome
    execution.helperMutationRequested = start.receipt.requestSent
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selection.selectedRoutes,
        start: start,
        budget: budget
      )
    }
    if start.receipt.transportAcknowledged, start.lease != nil {
      let postStart = await dependencies.observeGeneration(budget.work)
      if applyWorkAbortIfNeeded(&execution, budget: budget) {
        return await finish(
          &execution,
          baseline: baseline,
          coldGeneration: coldGeneration,
          authorizationLease: authorizationLease,
          selectedRoutes: selection.selectedRoutes,
          start: start,
          budget: budget
        )
      }
      if !ProductM2GenerationFence.singleRunningGeneration(
        coldGeneration,
        postStart
      ) {
        execution.fail(
          .generationFenceRejected,
          event: .postStartGenerationRejected,
          state: .failed
        )
      }
    } else {
      execution.fail(.startRejected, event: .startControlRejected, state: .failed)
    }

    if execution.firstBadEvent == nil {
      await proveVendorStatusAndActiveNetwork(
        &execution,
        baseline: baseline,
        selectedRoutes: selection.selectedRoutes,
        controlLease: start.lease,
        budget: budget
      )
    }
    if execution.firstBadEvent == nil {
      await proveFreshSSH(&execution, budget: budget)
    }
    return await finish(
      &execution,
      baseline: baseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selection.selectedRoutes,
      start: start,
      budget: budget
    )
  }

  private func proveVendorStatusAndActiveNetwork(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    selectedRoutes: VendorCharonSelectedRouteMatcher,
    controlLease: ProductM2ControlLease?,
    budget: ProductM2AbsoluteBudget
  ) async {
    guard let controlLease else {
      execution.fail(.startRejected, event: .startControlRejected, state: .failed)
      return
    }
    guard let statusTimeout = budget.work.remainingMilliseconds(cappedAt: 2_000) else {
      _ = applyWorkAbortIfNeeded(&execution, budget: budget)
      return
    }
    let status = await controlLease.waitForConnectedStatus(
      timeoutMilliseconds: statusTimeout
    )
    execution.vendorStatusEvidence = status
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return
    }
    if status.outcome == .cancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return
    }
    guard status.connectedProven else {
      execution.fail(
        .vendorStatusUnproven,
        event: .vendorStatusUnproven,
        state: .failed
      )
      return
    }

    guard
      let active = await dependencies.captureNetworkBaseline(
        execution.networkWindow,
        selectedRoutes,
        budget.work
      )
    else {
      if applyWorkAbortIfNeeded(&execution, budget: budget) {
        return
      }
      execution.fail(
        .activeNetworkUnproven,
        event: .activeNetworkUnproven,
        state: .failed
      )
      return
    }
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return
    }
    let evidence = dependencies.assessActiveConnection(baseline, active)
    execution.activeNetworkEvidence = evidence
    if !evidence.connectionProven {
      execution.fail(
        .activeNetworkUnproven,
        event: .activeNetworkUnproven,
        state: .failed
      )
    }
  }

  private func proveFreshSSH(
    _ execution: inout ProductM2Execution,
    budget: ProductM2AbsoluteBudget
  ) async {
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      execution.sshProof = budget.work.hasRemaining ? .cancelled : .timedOut
      return
    }
    let rawEvidence = await dependencies.proveFreshSSH(
      execution.request.sshTarget,
      budget.work
    )
    let evidence = normalizedEvidence(
      rawEvidence,
      requestedTarget: execution.request.sshTarget
    )
    execution.sshProofEvidence = evidence
    execution.sshProof = evidence.outcome
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return
    }
    if execution.sshProof == .proven {
      execution.outcome = .connectedAndCleanedUp
    } else {
      execution.fail(.sshProofRejected, event: .sshProofRejected, state: .failed)
    }
  }

  private func normalizedEvidence(
    _ evidence: ProductM2FreshSSHProofEvidence,
    requestedTarget: ProductM2SSHTarget
  ) -> ProductM2FreshSSHProofEvidence {
    guard evidence.outcome == .proven else { return evidence }
    let consistent =
      evidence.target == requestedTarget
      && evidence.processStarted && evidence.processReaped
      && evidence.freshTransportForced && evidence.strictHostKeyPolicy
      && evidence.exitStatusZero && evidence.challengeMatched
      && evidence.standardOutputWithinLimit && evidence.standardErrorWithinLimit
      && !evidence.timedOut && !evidence.cancelled
    guard !consistent else { return evidence }
    return ProductM2FreshSSHProofEvidence(
      target: evidence.target,
      outcome: .rejected,
      processStarted: evidence.processStarted,
      processReaped: evidence.processReaped,
      exitStatusZero: evidence.exitStatusZero,
      challengeMatched: evidence.challengeMatched,
      standardOutputWithinLimit: evidence.standardOutputWithinLimit,
      standardErrorWithinLimit: evidence.standardErrorWithinLimit,
      timedOut: evidence.timedOut,
      cancelled: evidence.cancelled
    )
  }
}
