extension VendorCharonControlState {
  func stop(
    timeoutMilliseconds: Int
  ) async -> VendorCharonControlReceipt {
    guard RawVendorCharonControlTransport.validTimeoutMilliseconds.contains(timeoutMilliseconds)
    else { return await immediateStop(.invalidTimeout) }
    guard !Task.isCancelled else { return await immediateStop(.cancelled) }

    let attempt = StopAttempt()
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        queue.async { [self] in
          guard phase == .active, stopContinuation == nil else {
            continuation.resume(
              returning: makeUnsentStopReceipt(
                .leaseClosed,
                connectionRetained: phase == .active || phase == .stopping
              ))
            return
          }
          guard !attempt.isCancelled else {
            continuation.resume(
              returning: makeUnsentStopReceipt(.cancelled, connectionRetained: true))
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
        guard currentStopAttempt === attempt else { return }
        if phase == .stopping { finishStop(.cancelled, retainConnection: false) }
      }
    }
  }
}
