import PowerVPNCore

extension ProductM2ConnectOnceCoordinator {
  func startProveAndFinish(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease,
    selection: ProductM2AuthorizedResourceSelection
  ) async -> ProductM2ConnectReport {
    let validator = replyValidator(before: coldGeneration)
    let pending: ProductM2PendingStart
    do {
      pending = try await selection.beginStart(
        control: dependencies.control,
        peerGenerationValidator: validator
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
        selectedRoutes: selection.selectedRoutes
      )
    }

    execution.lastGoodState = .connecting
    let start =
      await pending.result()
    execution.startOutcome = start.receipt.outcome
    execution.helperMutationRequested = start.receipt.requestSent
    if start.receipt.transportAcknowledged, start.lease != nil {
      let postStart = await dependencies.observeGeneration()
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
        controlLease: start.lease
      )
    }
    if execution.firstBadEvent == nil {
      await proveFreshSSH(&execution)
    }
    return await finish(
      &execution,
      baseline: baseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selectedRoutes: selection.selectedRoutes,
      controlLease: start.lease,
      startReceipt: start.receipt
    )
  }

  private func proveVendorStatusAndActiveNetwork(
    _ execution: inout ProductM2Execution,
    baseline: ProductM2NetworkBaseline,
    selectedRoutes: VendorCharonSelectedRouteMatcher,
    controlLease: ProductM2ControlLease?
  ) async {
    guard let controlLease else {
      execution.fail(.startRejected, event: .startControlRejected, state: .failed)
      return
    }
    let status = await controlLease.waitForConnectedStatus()
    execution.vendorStatusEvidence = status
    if Task.isCancelled || status.outcome == .cancelled {
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
        selectedRoutes
      )
    else {
      execution.fail(
        .activeNetworkUnproven,
        event: .activeNetworkUnproven,
        state: .failed
      )
      return
    }
    let evidence = dependencies.assessActiveConnection(baseline, active)
    execution.activeNetworkEvidence = evidence
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
    } else if !evidence.connectionProven {
      execution.fail(
        .activeNetworkUnproven,
        event: .activeNetworkUnproven,
        state: .failed
      )
    }
  }

  private func proveFreshSSH(
    _ execution: inout ProductM2Execution
  ) async {
    if Task.isCancelled {
      execution.sshProof = .cancelled
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return
    }
    let rawEvidence = await dependencies.proveFreshSSH(execution.request.sshTarget)
    let evidence = normalizedEvidence(
      rawEvidence,
      requestedTarget: execution.request.sshTarget
    )
    execution.sshProofEvidence = evidence
    execution.sshProof = evidence.outcome
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
    } else if execution.sshProof == .proven {
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
