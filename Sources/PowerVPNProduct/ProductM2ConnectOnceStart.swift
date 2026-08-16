import PowerVPNCore

extension ProductPersistentTunnelCoordinator {
  func startAndOpen(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease,
    selection: ProductM2AuthorizedResourceSelection,
    mutationLease: any ProductMutationLeaseHolding,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelSessionOpenResult {
    guard budget.work.hasRemaining else {
      _ = applyWorkAbortIfNeeded(&execution, budget: budget)
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

    let pending: ProductM2PendingStart
    do {
      pending = try await selection.beginStart(
        control: dependencies.control,
        deadline: budget.work,
        peerGenerationValidator: replyValidator(before: coldGeneration, deadline: budget.work)
      )
    } catch ProductM2AuthorizedResourceSelectionError.workAborted {
      if !applyWorkAbortIfNeeded(&execution, budget: budget) {
        execution.fail(.startSnapshotRejected, event: .startSnapshotRejected, state: .blocked)
      }
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, nil, budget)
    } catch {
      execution.fail(.startSnapshotRejected, event: .startSnapshotRejected, state: .blocked)
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, nil, budget)
    }

    execution.lastGoodState = .connecting
    let start = await pending.result()
    execution.startOutcome = start.receipt.outcome
    execution.startEventSignatures = start.receipt.startEventSignatures
    execution.startReplySignatures = start.receipt.startReplySignatures
    execution.unexpectedEventSignature = start.receipt.unexpectedEventSignature
    execution.startReplyUnavailableObserved = start.receipt.replyUnavailableObserved
    execution.startCompletionSource = start.receipt.completionSource
    execution.helperMutationRequested = start.receipt.requestSent
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }

    guard start.receipt.transportAcknowledged, start.lease != nil else {
      execution.fail(.startRejected, event: .startControlRejected, state: .failed)
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }

    let postStart = await dependencies.observeGeneration(budget.work)
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }
    guard ProductM2GenerationFence.singleRunningGeneration(coldGeneration, postStart) else {
      execution.fail(
        .generationFenceRejected,
        event: .postStartGenerationRejected,
        state: .failed
      )
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }
    guard
      await proveStartupNetwork(
        &execution,
        baseline: baseline,
        selectedRoutes: selection.selectedRoutes,
        controlLease: start.lease,
        coldGeneration: coldGeneration,
        budget: budget
      )
    else {
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }

    let authorizationMaterialErased = await authorizationLease.eraseStartMaterial()
    execution.authorizationOwnedMaterialErased = authorizationMaterialErased
    guard authorizationMaterialErased else {
      execution.fail(
        .cleanupUnproven,
        event: .authorizationCloseRejected,
        state: .failed
      )
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finishStartFailure(
        &execution, baseline, coldGeneration, authorizationLease, selection,
        mutationLease, start, budget)
    }

    execution.finalState = .connected
    return .active(
      ProductPersistentTunnelSessionAssets(
        execution: execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        selectedRoutes: selection.selectedRoutes,
        controlAuthority: ProductM2ControlCleanupAuthority(
          lease: start.lease,
          provisionalStop: start.provisionalStopCapability,
          emergencyStop: start.emergencyStopCapability,
          routeActivation: execution.routeActivation,
          startReceipt: start.receipt
        ),
        authorizationLease: authorizationLease,
        mutationLease: mutationLease
      ))
  }

  private func proveStartupNetwork(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    selectedRoutes: VendorCharonSelectedRouteMatcher,
    controlLease: ProductM2ControlLease?,
    coldGeneration: VendorHelperGenerationSnapshot,
    budget: ProductM2AbsoluteBudget
  ) async -> Bool {
    await proveVendorStatus(&execution, controlLease: controlLease, budget: budget)
    guard execution.firstBadEvent == nil else { return false }
    await awaitVendorStatusQuiescence(controlLease: controlLease, budget: budget)
    guard execution.firstBadEvent == nil else { return false }
    await activateSelectedNCRoutes(
      &execution,
      controlLease: controlLease,
      coldGeneration: coldGeneration,
      budget: budget
    )
    guard execution.firstBadEvent == nil else { return false }
    guard captureActiveDiagnosticsBeforeOpen else { return true }
    await captureActiveNetworkDiagnostics(
      &execution,
      baseline: baseline,
      selectedRoutes: selectedRoutes,
      deadline: budget.work
    )
    return !applyWorkAbortIfNeeded(&execution, budget: budget)
  }

  private func proveVendorStatus(
    _ execution: inout ProductM2Execution,
    controlLease: ProductM2ControlLease?,
    budget: ProductM2AbsoluteBudget
  ) async {
    guard let controlLease else {
      execution.fail(.startRejected, event: .startControlRejected, state: .failed)
      return
    }
    execution.activeCaptureState = .notAttempted
    guard let statusTimeout = budget.work.remainingMilliseconds(cappedAt: 2_000) else {
      _ = applyWorkAbortIfNeeded(&execution, budget: budget)
      return
    }
    let status = await controlLease.waitForConnectedStatus(timeoutMilliseconds: statusTimeout)
    execution.vendorStatusEvidence = status
    if applyWorkAbortIfNeeded(&execution, budget: budget) { return }
    if status.outcome == .cancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return
    }
    guard status.connectedProven else {
      execution.fail(.vendorStatusUnproven, event: .vendorStatusUnproven, state: .failed)
      return
    }
  }

  private func awaitVendorStatusQuiescence(
    controlLease: ProductM2ControlLease?,
    budget: ProductM2AbsoluteBudget
  ) async {
    let quietWindowMilliseconds = 400
    let pollIntervalMilliseconds = 25
    guard let controlLease,
      let waitCapMilliseconds = budget.work.remainingMilliseconds(cappedAt: 800)
    else { return }

    let clock = ContinuousClock()
    let startedAt = clock.now
    let hardDeadline = startedAt.advanced(by: .milliseconds(waitCapMilliseconds))
    var quietDeadline = startedAt.advanced(by: .milliseconds(quietWindowMilliseconds))
    var statusEventCount = controlLease.statusEventCount

    while !Task.isCancelled {
      let now = clock.now
      if now >= quietDeadline || now >= hardDeadline { return }
      guard budget.work.hasRemaining else { return }
      let pollDeadline = now.advanced(by: .milliseconds(pollIntervalMilliseconds))
      let nextDeadline = min(min(pollDeadline, quietDeadline), hardDeadline)
      do {
        try await clock.sleep(until: nextDeadline)
      } catch {
        return
      }
      let currentStatusEventCount = controlLease.statusEventCount
      if currentStatusEventCount != statusEventCount {
        statusEventCount = currentStatusEventCount
        quietDeadline = clock.now.advanced(by: .milliseconds(quietWindowMilliseconds))
      }
    }
  }

  private func activateSelectedNCRoutes(
    _ execution: inout ProductM2Execution,
    controlLease: ProductM2ControlLease?,
    coldGeneration: VendorHelperGenerationSnapshot,
    budget: ProductM2AbsoluteBudget
  ) async {
    guard let controlLease,
      let timeout = budget.work.remainingMilliseconds(cappedAt: 2_000)
    else {
      _ = applyWorkAbortIfNeeded(&execution, budget: budget)
      if execution.firstBadEvent == nil {
        execution.fail(
          .routeActivationRejected,
          event: .routeActivationRejected,
          state: .failed
        )
      }
      return
    }
    let receipt = await controlLease.setSelectedNCEnabled(
      true,
      timeoutMilliseconds: timeout,
      peerGenerationValidator: replyValidator(
        before: coldGeneration,
        deadline: budget.work
      )
    )
    execution.routeActivation = receipt
    execution.helperMutationRequested =
      execution.helperMutationRequested || receipt.requestSent
    if applyWorkAbortIfNeeded(&execution, budget: budget) { return }
    guard receipt.transportAcknowledged else {
      execution.fail(
        .routeActivationRejected,
        event: .routeActivationRejected,
        state: .failed
      )
      return
    }
  }

  /// Records the host-side active-network assessment without deciding the
  /// connect-once outcome. The caller owns deadline/cancellation policy so the
  /// persistent open path can remain fail-closed while post-SSH diagnostics
  /// cannot overwrite the decisive proof or suppress cleanup.
  func captureActiveNetworkDiagnostics(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    selectedRoutes: VendorCharonSelectedRouteMatcher,
    deadline: ProductM2StageDeadline
  ) async {
    let capture = await dependencies.captureNetworkBaseline(
      execution.networkWindow,
      selectedRoutes,
      deadline
    )
    execution.activeCaptureState = capture.state
    execution.activeCaptureChangeAxes = capture.changeAxes.isEmpty ? nil : capture.changeAxes
    execution.activeCaptureIncompleteReason = capture.incompleteReason
    guard let active = capture.baseline else { return }
    execution.activeNetworkEvidence = dependencies.assessActiveConnection(baseline, active)
  }

  func proveFreshSSH(
    _ execution: inout ProductM2Execution,
    budget: ProductM2AbsoluteBudget
  ) async {
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      execution.sshProof = budget.work.hasRemaining ? .cancelled : .timedOut
      return
    }
    let rawEvidence = await dependencies.proveFreshSSH(execution.request.sshTarget, budget.work)
    let evidence = normalizedEvidence(rawEvidence, requestedTarget: execution.request.sshTarget)
    execution.sshProofEvidence = evidence
    execution.sshProof = evidence.outcome
    if applyWorkAbortIfNeeded(&execution, budget: budget) { return }
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
      && evidence.failureClass == nil
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
      cancelled: evidence.cancelled,
      failureClass: .unclassified
    )
  }
}
