extension VendorCharonControlState {
  func beginPeerGenerationValidation() {
    guard phase == .starting, validation == nil,
      let validator = currentValidator
    else { return }
    validation = VendorCharonAsyncValidation(operation: validator) { [weak self] accepted in
      guard let self else { return }
      self.queue.async { [weak self] in
        self?.completePeerGenerationValidation(accepted)
      }
    }
  }

  private func completePeerGenerationValidation(
    _ accepted: Bool
  ) {
    guard phase == .starting else { return }
    validation = nil
    finishStart(accepted ? .transportAcknowledged : .peerGenerationMismatch)
  }

  private func cancelPeerGenerationValidation() {
    validation?.cancel()
    validation = nil
  }

  func handleSubmission(
    _ submission: VendorXPCSessionSubmission,
    operation: VendorCharonControlOperation
  ) {
    switch submission {
    case .submitted:
      requestSent = true
    case .rejected(let outcome):
      requestSent = false
      if operation == .startConnection {
        finishStart(outcome)
      } else {
        finishStop(outcome, retainConnection: false)
      }
    }
  }

  func finishStart(
    _ outcome: VendorCharonControlOutcome,
    sealSubmittedSession: Bool = false,
    encodingError: VendorCharonStartEncodingError? = nil
  ) {
    guard phase == .starting else { return }
    timer?.cancel()
    timer = nil
    cancelPeerGenerationValidation()
    currentValidator = nil
    snapshot = nil
    let acknowledged = outcome == .transportAcknowledged
    let cleanupCapable = !acknowledged && requestSent && driver != nil
    let provisional = cleanupCapable && !sealSubmittedSession
    let cancelled = acknowledged || provisional ? false : cancelDriver()
    let retainedStopContext = requestSent ? stopContext : nil
    phase = acknowledged ? .active : provisional ? .provisional : .closed
    let receipt = makeReceipt(
      operation: .startConnection,
      outcome: outcome,
      connectionRetained: acknowledged,
      cancelRequested: cancelled,
      encodingError: encodingError
    )
    let result = VendorCharonStartControlResult(
      receipt: receipt,
      lease: acknowledged ? VendorCharonControlLease(state: self) : nil,
      provisionalStopCapability:
        cleanupCapable ? VendorCharonProvisionalStopCapability(state: self) : nil,
      stopContext: retainedStopContext
    )
    if !acknowledged && !provisional {
      stopContext = nil
      ncRouteToggleContext = nil
    }
    if let continuation = startContinuation {
      startContinuation = nil
      continuation.resume(returning: result)
    } else {
      completedStartResult = result
    }
  }

  func finishStop(
    _ outcome: VendorCharonControlOutcome,
    retainConnection: Bool
  ) {
    guard let continuation = stopContinuation else { return }
    timer?.cancel()
    timer = nil
    cancelPeerGenerationValidation()
    currentValidator = nil
    let finishingAttempt = currentStopAttempt
    currentStopAttempt = nil
    let acknowledged = outcome == .transportAcknowledged
    let cancelled: Bool
    if retainConnection {
      cancelled = false
    } else if acknowledged {
      armPostStopDrain(attempt: finishingAttempt)
      cancelled = false
    } else {
      cancelled = cancelDriver()
    }
    phase = retainConnection ? .active : .closed
    var receipt = makeReceipt(
      operation: .stopConnection,
      outcome: outcome,
      connectionRetained: retainConnection,
      cancelRequested: cancelled
    )
    receipt.statusAtSubmission = stopStatusAtSubmission
    stopStatusAtSubmission = nil
    if !retainConnection {
      stopContext = nil
      ncRouteToggleContext = nil
    }
    stopContinuation = nil
    continuation.resume(returning: receipt)
  }

  func immediateStop(
    _ outcome: VendorCharonControlOutcome,
    allowedPhase: Phase = .active
  ) async -> VendorCharonControlReceipt {
    await withCheckedContinuation { continuation in
      queue.async { [self] in
        let leaseClosed = phase != allowedPhase
        let cancelled = leaseClosed && postStopDrain != nil && cancelDriver()
        continuation.resume(
          returning: makeUnsentStopReceipt(
            leaseClosed ? .leaseClosed : outcome,
            connectionRetained: allowedPhase == .active && phase == .active,
            cancelRequested: cancelled
          ))
      }
    }
  }

  func makeUnsentStopReceipt(
    _ outcome: VendorCharonControlOutcome,
    connectionRetained: Bool,
    cancelRequested: Bool = false
  ) -> VendorCharonControlReceipt {
    VendorCharonControlReceipt(
      operation: .stopConnection,
      outcome: outcome,
      requestSent: false,
      emptyReplyObserved: false,
      peerGenerationValidated: false,
      connectionRetained: connectionRetained,
      connectionCancelRequested: cancelRequested,
      encodingError: nil,
      statusEventCount: observation.statusEventCount,
      dispatcherTailEventCount: observation.dispatcherTailEventCount
    )
  }

  func makeReceipt(
    operation: VendorCharonControlOperation,
    outcome: VendorCharonControlOutcome,
    connectionRetained: Bool,
    cancelRequested: Bool,
    requestWasSent: Bool? = nil,
    encodingError: VendorCharonStartEncodingError? = nil
  ) -> VendorCharonControlReceipt {
    let observation = observation
    return VendorCharonControlReceipt(
      operation: operation,
      outcome: outcome,
      requestSent: requestWasSent ?? requestSent,
      emptyReplyObserved: emptyReplyObserved,
      peerGenerationValidated: outcome == .transportAcknowledged,
      connectionRetained: connectionRetained,
      connectionCancelRequested: cancelRequested,
      encodingError: encodingError,
      statusEventCount: observation.statusEventCount,
      dispatcherTailEventCount: observation.dispatcherTailEventCount,
      incomingEventSignatures: observation.incomingEventSignatures,
      replySignatures: observation.replySignatures,
      unexpectedEventSignature:
        operation == .startConnection ? startUnexpectedEventSignature : nil
    )
  }

  private func armPostStopDrain(attempt: StopAttempt?) {
    guard postStopDrain == nil, let current = driver else { return }
    driver = nil
    let drain = VendorCharonControlConnectionDrain(
      cancelDriver: { current.cancel() },
      scheduler: postStopDrainScheduler
    )
    postStopDrain = drain
    postStopDrainAttempt = attempt
    drain.arm(on: queue)
  }

  func cancelDriver() -> Bool {
    if let drain = postStopDrain {
      postStopDrain = nil
      postStopDrainAttempt = nil
      let cancelled = drain.cancelNow()
      cancelIssued = cancelIssued || cancelled
      return cancelled
    }
    guard !cancelIssued, let current = driver else { return false }
    cancelIssued = true
    driver = nil
    current.cancel()
    return true
  }

  func updateObservation(_ body: () -> Void) {
    observationLock.withLock(body)
  }
}
