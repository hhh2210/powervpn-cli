import Dispatch
import Foundation

struct VendorCharonNCRouteToggleContext: Sendable {
  private let tunnelNameCString: [CChar]

  init(tunnelNameCString: [CChar]) {
    precondition(tunnelNameCString.count > 1 && tunnelNameCString.last == 0)
    self.tunnelNameCString = tunnelNameCString
  }

  func withTunnelNameCString<Result>(
    _ body: (UnsafePointer<CChar>) throws -> Result
  ) rethrows -> Result {
    try tunnelNameCString.withUnsafeBufferPointer { buffer in
      try body(buffer.baseAddress!)
    }
  }
}

extension VendorCharonControlState {
  func setSelectedNCEnabled(
    _ enabled: Bool,
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> VendorCharonControlReceipt {
    let attempt = VendorCharonNCRouteToggleAttempt()
    if Task.isCancelled {
      _ = attempt.cancel()
      return await immediateNCRouteToggle(.cancelled)
    }
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        queue.async { [self] in
          beginNCRouteToggle(
            enabled,
            timeoutMilliseconds: timeoutMilliseconds,
            peerGenerationValidator: peerGenerationValidator,
            attempt: attempt,
            continuation: continuation
          )
        }
      }
    } onCancel: {
      guard let identity = attempt.cancel() else { return }
      self.queue.async { [weak self] in
        self?.finishNCRouteToggle(
          .cancelled,
          retainConnection: true,
          attempt: identity
        )
      }
    }
  }

  private func beginNCRouteToggle(
    _ enabled: Bool,
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    attempt: VendorCharonNCRouteToggleAttempt,
    continuation: CheckedContinuation<VendorCharonControlReceipt, Never>
  ) {
    guard !attempt.isCancelled else {
      continuation.resume(
        returning: makeReceipt(
          operation: .resourceToggleNC,
          outcome: .cancelled,
          connectionRetained: phase == .active,
          cancelRequested: false,
          requestWasSent: false
        ))
      return
    }
    guard timeoutMilliseconds > 0 else {
      continuation.resume(
        returning: makeReceipt(
          operation: .resourceToggleNC,
          outcome: .invalidTimeout,
          connectionRetained: phase == .active,
          cancelRequested: false,
          requestWasSent: false
        ))
      return
    }
    guard phase == .active, let context = ncRouteToggleContext, let driver else {
      continuation.resume(
        returning: makeReceipt(
          operation: .resourceToggleNC,
          outcome: phase == .active ? .snapshotEncodingFailed : .leaseClosed,
          connectionRetained: phase == .active,
          cancelRequested: false,
          requestWasSent: false
        ))
      return
    }

    precondition(ncRouteToggleAttemptSequence < UInt64.max)
    ncRouteToggleAttemptSequence += 1
    let identity = ncRouteToggleAttemptSequence
    guard attempt.activate(identity: identity) else {
      continuation.resume(
        returning: makeReceipt(
          operation: .resourceToggleNC,
          outcome: .cancelled,
          connectionRetained: true,
          cancelRequested: false,
          requestWasSent: false
        ))
      return
    }
    phase = .togglingNC
    activeNCRouteToggleAttempt = identity
    ncRouteToggleContinuation = continuation
    ncRouteToggleValidator = peerGenerationValidator
    ncRouteToggleAcknowledgementObserved = false
    requestSent = false
    emptyReplyObserved = false
    updateObservation { replySignatures = [] }
    armNCRouteToggleTimeout(
      milliseconds: timeoutMilliseconds,
      attempt: identity
    )
    let request = VendorCharonControlWireCodec.makeNCRouteToggleRequest(
      context: context,
      enabled: enabled
    )
    let submission = driver.submit(request) { [weak self] event in
      guard let self else { return }
      self.queue.async {
        self.handleNCRouteToggleReply(
          event,
          attempt: identity
        )
      }
    }
    switch submission {
    case .submitted:
      ncRouteToggleOrdinaryAcknowledgementAttempts.append(identity)
      requestSent = true
    case .rejected(let outcome):
      finishNCRouteToggle(
        outcome,
        retainConnection: false,
        attempt: identity
      )
    }
  }

  private func handleNCRouteToggleReply(
    _ event: VendorCharonControlReplyEvent,
    attempt: UInt64
  ) {
    guard phase == .togglingNC, activeNCRouteToggleAttempt == attempt else {
      return
    }
    if case .decodedDictionary(let signature, let decoded) = event {
      recordReplyWireSignature(signature)
      handleNCRouteToggleReply(
        decoded,
        attempt: attempt
      )
      return
    }
    switch event {
    case .decodedDictionary:
      return
    case .ncRouteToggleAcknowledgement(let success):
      handleNCRouteToggleAcknowledgement(success, attempt: attempt)
    case .emptyAcknowledgement, .unexpectedPayload:
      finishNCRouteToggle(
        .unexpectedReplyPayload,
        retainConnection: true,
        attempt: attempt
      )
    case .connectionInterrupted, .connectionInvalid, .peerCodeSigningRequirement,
      .unexpectedXPCError:
      finishNCRouteToggle(
        ncRouteToggleTerminalOutcome(event),
        retainConnection: false,
        attempt: attempt
      )
    }
  }

  func consumeNCRouteToggleOrdinaryAcknowledgementAttempt() -> UInt64? {
    guard
      ncRouteToggleOrdinaryAcknowledgementHead
        < ncRouteToggleOrdinaryAcknowledgementAttempts.count
    else {
      return nil
    }
    let attempt =
      ncRouteToggleOrdinaryAcknowledgementAttempts[ncRouteToggleOrdinaryAcknowledgementHead]
    ncRouteToggleOrdinaryAcknowledgementHead += 1
    if ncRouteToggleOrdinaryAcknowledgementHead >= 32,
      ncRouteToggleOrdinaryAcknowledgementHead
        >= ncRouteToggleOrdinaryAcknowledgementAttempts.count
        - ncRouteToggleOrdinaryAcknowledgementHead
    {
      ncRouteToggleOrdinaryAcknowledgementAttempts.removeFirst(
        ncRouteToggleOrdinaryAcknowledgementHead
      )
      ncRouteToggleOrdinaryAcknowledgementHead = 0
    }
    return attempt
  }

  func handleNCRouteToggleAcknowledgement(
    _ success: Bool,
    attempt: UInt64
  ) {
    guard phase == .togglingNC,
      activeNCRouteToggleAttempt == attempt,
      !ncRouteToggleAcknowledgementObserved
    else {
      return
    }
    ncRouteToggleAcknowledgementObserved = true
    guard success else {
      finishNCRouteToggle(
        .helperRejected,
        retainConnection: true,
        attempt: attempt
      )
      return
    }
    guard let validator = ncRouteToggleValidator else {
      finishNCRouteToggle(
        .unexpectedXPCError,
        retainConnection: false,
        attempt: attempt
      )
      return
    }
    ncRouteToggleValidation = VendorCharonAsyncValidation(
      operation: validator
    ) { [weak self] accepted in
      guard let self else { return }
      self.queue.async {
        self.completeNCRouteToggleValidation(
          accepted,
          attempt: attempt
        )
      }
    }
  }

  private func ncRouteToggleTerminalOutcome(
    _ event: VendorCharonControlReplyEvent
  ) -> VendorCharonControlOutcome {
    switch event {
    case .connectionInterrupted: return .connectionInterrupted
    case .connectionInvalid: return .connectionInvalid
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .unexpectedXPCError: return .unexpectedXPCError
    default: preconditionFailure("non-terminal NC route-toggle event")
    }
  }

  private func completeNCRouteToggleValidation(
    _ accepted: Bool,
    attempt: UInt64
  ) {
    guard phase == .togglingNC, activeNCRouteToggleAttempt == attempt else {
      return
    }
    ncRouteToggleValidation = nil
    finishNCRouteToggle(
      accepted ? .transportAcknowledged : .peerGenerationMismatch,
      retainConnection: true,
      attempt: attempt
    )
  }

  private func armNCRouteToggleTimeout(milliseconds: Int, attempt: UInt64) {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + .milliseconds(milliseconds))
    timer.setEventHandler { [weak self] in
      self?.finishNCRouteToggle(
        .timeout,
        retainConnection: true,
        attempt: attempt
      )
    }
    self.timer = timer
    timer.resume()
  }

  func finishNCRouteToggle(
    _ outcome: VendorCharonControlOutcome,
    retainConnection: Bool,
    attempt: UInt64
  ) {
    guard phase == .togglingNC,
      activeNCRouteToggleAttempt == attempt,
      let continuation = ncRouteToggleContinuation
    else {
      return
    }
    activeNCRouteToggleAttempt = nil
    timer?.cancel()
    timer = nil
    ncRouteToggleValidation?.cancel()
    ncRouteToggleValidation = nil
    ncRouteToggleValidator = nil
    ncRouteToggleAcknowledgementObserved = false
    let cancelled = retainConnection ? false : cancelDriver()
    phase = retainConnection ? .active : .closed
    let receipt = makeReceipt(
      operation: .resourceToggleNC,
      outcome: outcome,
      connectionRetained: retainConnection,
      cancelRequested: cancelled
    )
    if !retainConnection {
      stopContext = nil
      ncRouteToggleContext = nil
    }
    ncRouteToggleContinuation = nil
    continuation.resume(returning: receipt)
  }

  private func immediateNCRouteToggle(
    _ outcome: VendorCharonControlOutcome
  ) async -> VendorCharonControlReceipt {
    await withCheckedContinuation { continuation in
      queue.async { [self] in
        continuation.resume(
          returning: makeReceipt(
            operation: .resourceToggleNC,
            outcome: outcome,
            connectionRetained: phase == .active,
            cancelRequested: false,
            requestWasSent: false
          ))
      }
    }
  }
}
