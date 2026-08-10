extension VendorCharonControlState {
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
    encodingError: VendorCharonStartEncodingError? = nil
  ) {
    guard phase == .starting else { return }
    timer?.cancel()
    timer = nil
    currentValidator = nil
    snapshot = nil
    let acknowledged = outcome == .transportAcknowledged
    let cancelled = acknowledged ? false : cancelDriver()
    phase = acknowledged ? .active : .closed
    let receipt = makeReceipt(
      operation: .startConnection,
      outcome: outcome,
      connectionRetained: acknowledged,
      cancelRequested: cancelled,
      encodingError: encodingError
    )
    let result = VendorCharonStartControlResult(
      receipt: receipt,
      lease: acknowledged ? VendorCharonControlLease(state: self) : nil
    )
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
    currentValidator = nil
    currentStopAttempt = nil
    let cancelled = retainConnection ? false : cancelDriver()
    phase = retainConnection ? .active : .closed
    let receipt = makeReceipt(
      operation: .stopConnection,
      outcome: outcome,
      connectionRetained: retainConnection,
      cancelRequested: cancelled
    )
    stopContinuation = nil
    continuation.resume(returning: receipt)
  }

  func immediateStop(
    _ outcome: VendorCharonControlOutcome
  ) async -> VendorCharonControlReceipt {
    await withCheckedContinuation { continuation in
      queue.async { [self] in
        continuation.resume(
          returning: makeUnsentStopReceipt(
            phase == .active ? outcome : .leaseClosed,
            connectionRetained: phase == .active
          ))
      }
    }
  }

  func makeUnsentStopReceipt(
    _ outcome: VendorCharonControlOutcome,
    connectionRetained: Bool
  ) -> VendorCharonControlReceipt {
    VendorCharonControlReceipt(
      operation: .stopConnection,
      outcome: outcome,
      requestSent: false,
      emptyReplyObserved: false,
      peerGenerationValidated: false,
      connectionRetained: connectionRetained,
      connectionCancelRequested: false,
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
    VendorCharonControlReceipt(
      operation: operation,
      outcome: outcome,
      requestSent: requestWasSent ?? requestSent,
      emptyReplyObserved: emptyReplyObserved,
      peerGenerationValidated: outcome == .transportAcknowledged,
      connectionRetained: connectionRetained,
      connectionCancelRequested: cancelRequested,
      encodingError: encodingError,
      statusEventCount: observation.statusEventCount,
      dispatcherTailEventCount: observation.dispatcherTailEventCount
    )
  }

  func cancelDriver() -> Bool {
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
