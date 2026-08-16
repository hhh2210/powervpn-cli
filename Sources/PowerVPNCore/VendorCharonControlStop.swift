extension VendorCharonControlState {
  func stop(
    timeoutMilliseconds: Int
  ) async -> VendorCharonControlReceipt {
    await stop(
      timeoutMilliseconds: timeoutMilliseconds,
      allowedPhase: .active
    )
  }

  func stopProvisional(
    timeoutMilliseconds: Int
  ) async -> VendorCharonControlReceipt {
    await stop(
      timeoutMilliseconds: timeoutMilliseconds,
      allowedPhase: .provisional
    )
  }

  private func stop(
    timeoutMilliseconds: Int,
    allowedPhase: Phase
  ) async -> VendorCharonControlReceipt {
    guard RawVendorCharonControlTransport.validTimeoutMilliseconds.contains(timeoutMilliseconds)
    else { return await immediateStop(.invalidTimeout, allowedPhase: allowedPhase) }
    guard !Task.isCancelled else {
      return await immediateStop(.cancelled, allowedPhase: allowedPhase)
    }

    let attempt = StopAttempt()
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        queue.async { [self] in
          guard phase == allowedPhase, stopContinuation == nil else {
            let cancelled = postStopDrain != nil && cancelDriver()
            continuation.resume(
              returning: makeUnsentStopReceipt(
                .leaseClosed,
                connectionRetained:
                  allowedPhase == .active && (phase == .active || phase == .stopping),
                cancelRequested: cancelled
              ))
            return
          }
          guard !attempt.isCancelled else {
            continuation.resume(
              returning: makeUnsentStopReceipt(
                .cancelled,
                connectionRetained: allowedPhase == .active
              ))
            return
          }
          finishStatusWait(.leaseClosed)
          stopStatusAtSubmission = latestStatus?.classification
          currentStopAttempt = attempt
          stopContinuation = continuation
          beginStop(timeoutMilliseconds: timeoutMilliseconds)
        }
      }
    } onCancel: {
      attempt.cancel()
      self.queue.async { [self] in
        if currentStopAttempt === attempt {
          completionSource = .callerCancel
          if phase == .stopping { finishStop(.cancelled, retainConnection: false) }
        } else if postStopDrainAttempt === attempt {
          _ = cancelDriver()
        }
      }
    }
  }
}
