import Dispatch
import Foundation

private struct VendorCharonStartAuthorizationCommitFailure: Error {
  let underlying: any Error
}
private enum VendorCharonWireSignatureChannel: String {
  case connection
  case reply
}

final class VendorCharonControlState: @unchecked Sendable {
  enum Phase { case idle, starting, provisional, active, togglingNC, stopping, closed }

  final class StopAttempt: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    var isCancelled: Bool { lock.withLock { cancelled } }

    func cancel() {
      lock.withLock { cancelled = true }
    }
  }

  let queue = DispatchQueue(label: "com.powervpn.vendor-charon-control")
  let observationLock = NSLock()
  let driverFactory: RawVendorCharonControlTransport.DriverFactory
  let postStopDrainScheduler: VendorCharonConnectionDrainScheduler
  var snapshot: VendorCharonStartSnapshot?
  var stopContext: VendorCharonStopContext?
  var ncRouteToggleContext: VendorCharonNCRouteToggleContext?
  var driver: (any VendorCharonControlConnectionDriving)?
  var postStopDrain: VendorCharonControlConnectionDrain?
  var phase = Phase.idle
  var timer: DispatchSourceTimer?
  var startContinuation: CheckedContinuation<VendorCharonStartControlResult, Never>?
  var completedStartResult: VendorCharonStartControlResult?
  var stopContinuation: CheckedContinuation<VendorCharonControlReceipt, Never>?
  var currentStopAttempt: StopAttempt?
  var postStopDrainAttempt: StopAttempt?
  var stopStatusAtSubmission: VendorCharonStatusClassification?
  var currentValidator: (@Sendable () async -> Bool)?
  var validation: VendorCharonAsyncValidation?
  var ncRouteToggleContinuation: CheckedContinuation<VendorCharonControlReceipt, Never>?
  var ncRouteToggleValidation: VendorCharonAsyncValidation?
  var ncRouteToggleAttemptSequence: UInt64 = 0
  var activeNCRouteToggleAttempt: UInt64?
  var requestSent = false
  var emptyReplyObserved = false
  var statusEvents = 0
  var latestStatus: VendorCharonStatusSignal?
  var latestTerminalStatus: VendorCharonStatusClassification?
  var statusWaitContinuation: CheckedContinuation<VendorCharonStatusWaitResult, Never>?
  var statusWaitTimer: DispatchSourceTimer?
  var currentStatusWaitAttempt: VendorCharonStatusWaitAttempt?
  var dispatcherTailEvents = 0
  var unexpectedDictionaryEvents = 0
  var terminalConnectionOutcome: VendorCharonControlOutcome?
  var incomingEventSignatures: [String] = []
  var replySignatures: [String] = []
  var startUnexpectedEventSignature: [String]?
  var wireSignatureSequence = 0
  var lastWireSignatureFingerprint: String?
  var cancelIssued = false

  init(
    snapshot: VendorCharonStartSnapshot,
    driverFactory: @escaping RawVendorCharonControlTransport.DriverFactory,
    postStopDrainScheduler: @escaping VendorCharonConnectionDrainScheduler =
      VendorCharonControlConnectionDrain.productionScheduler
  ) {
    self.snapshot = snapshot
    self.driverFactory = driverFactory
    self.postStopDrainScheduler = postStopDrainScheduler
  }

  var observation: VendorCharonControlObservation {
    observationLock.withLock {
      VendorCharonControlObservation(
        statusEventCount: statusEvents,
        latestStatus: latestStatus,
        dispatcherTailEventCount: dispatcherTailEvents,
        unexpectedDictionaryEventCount: unexpectedDictionaryEvents,
        incomingEventSignatures: incomingEventSignatures,
        replySignatures: replySignatures,
        terminalConnectionOutcome: terminalConnectionOutcome
      )
    }
  }

  func beginStartSynchronously(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    commitStartAuthorization: @Sendable () throws -> Void
  ) throws {
    try queue.sync {
      try beginStart(
        timeoutMilliseconds: timeoutMilliseconds,
        peerGenerationValidator: peerGenerationValidator,
        commitStartAuthorization: commitStartAuthorization
      )
    }
  }

  func awaitStartResult() async -> VendorCharonStartControlResult {
    if Task.isCancelled { cancelPendingStartWait() }
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        queue.async { [self] in
          if let completedStartResult {
            self.completedStartResult = nil
            continuation.resume(returning: completedStartResult)
            return
          }
          startContinuation = continuation
        }
      }
    } onCancel: {
      self.cancelPendingStartWait()
    }
  }

  func abandon() {
    queue.async { [self] in
      guard phase == .active || phase == .togglingNC || postStopDrain != nil else { return }
      if phase == .active { finishStatusWait(.leaseClosed) }
      if phase == .togglingNC, let attempt = activeNCRouteToggleAttempt {
        finishNCRouteToggle(.leaseClosed, retainConnection: false, attempt: attempt)
      } else {
        _ = cancelDriver()
        phase = .closed
      }
      stopContext = nil
      ncRouteToggleContext = nil
      activeNCRouteToggleAttempt = nil
    }
  }

  func abandonProvisionalStop() {
    queue.async { [self] in
      guard phase == .provisional || postStopDrain != nil else { return }
      _ = cancelDriver()
      phase = .closed
      stopContext = nil
    }
  }

  func discardPendingStart() {
    queue.async { [self] in
      if phase == .starting { finishStart(.cancelled) }
      guard completedStartResult != nil else { return }
      if phase == .active {
        _ = cancelDriver()
        phase = .closed
      }
      completedStartResult = nil
      stopContext = nil
      ncRouteToggleContext = nil
    }
  }

  private func cancelPendingStartWait() {
    queue.async { [self] in
      if phase == .starting { finishStart(.cancelled) }
    }
  }

  private func beginStart(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    commitStartAuthorization: @Sendable () throws -> Void
  ) throws {
    guard phase == .idle, let snapshot else {
      finishStart(.leaseClosed)
      return
    }
    phase = .starting
    currentValidator = peerGenerationValidator
    defer { self.snapshot = nil }
    do {
      try snapshot.withEncodedStartMessage { request in
        guard
          let stopContext = VendorCharonControlWireCodec.stopContext(
            copyingGatewayFromStartRequest: request
          )
        else {
          throw VendorCharonStartEncodingError.incompleteSnapshot(.gateway)
        }
        guard
          let ncRouteToggleContext =
            VendorCharonControlWireCodec.ncRouteToggleContext(
              copyingTunnelNameFromStartRequest: request
            )
        else {
          throw VendorCharonStartEncodingError.incompleteSnapshot(.tunnelName)
        }
        do {
          try commitStartAuthorization()
        } catch {
          throw VendorCharonStartAuthorizationCommitFailure(underlying: error)
        }
        self.stopContext = stopContext
        self.ncRouteToggleContext = ncRouteToggleContext
        let driver = driverFactory(queue) { [weak self] event in
          guard let self else { return }
          self.queue.async { self.handle(event) }
        }
        self.driver = driver
        armTimeout(milliseconds: timeoutMilliseconds, operation: .startConnection)
        let submission = driver.submit(request) { [weak self] event in
          guard let self else { return }
          self.queue.async { self.handle(event, operation: .startConnection) }
        }
        handleSubmission(submission, operation: .startConnection)
      }
    } catch let failure as VendorCharonStartAuthorizationCommitFailure {
      currentValidator = nil
      phase = .closed
      throw failure.underlying
    } catch let error as VendorCharonStartEncodingError {
      finishStart(.snapshotEncodingFailed, encodingError: error)
    } catch {
      finishStart(.snapshotEncodingFailed)
    }
  }

  func beginStop(timeoutMilliseconds: Int) {
    guard phase == .active || phase == .provisional,
      let driver,
      let stopContext
    else {
      requestSent = false
      finishStop(.snapshotEncodingFailed, retainConnection: false)
      return
    }
    phase = .stopping
    requestSent = false
    emptyReplyObserved = false
    armTimeout(milliseconds: timeoutMilliseconds, operation: .stopConnection)
    let submission = driver.submit(
      VendorCharonControlWireCodec.makeStopRequest(context: stopContext)
    ) { [weak self] event in
      guard let self else { return }
      self.queue.async { self.handle(event, operation: .stopConnection) }
    }
    handleSubmission(submission, operation: .stopConnection)
  }

  private func armTimeout(
    milliseconds: Int,
    operation: VendorCharonControlOperation
  ) {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + .milliseconds(milliseconds))
    timer.setEventHandler { [self] in
      if operation == .startConnection {
        finishStart(.timeout)
      } else {
        finishStop(.timeout, retainConnection: false)
      }
    }
    self.timer = timer
    timer.resume()
  }

  private func handle(
    _ event: VendorCharonControlReplyEvent,
    operation: VendorCharonControlOperation
  ) {
    if case .decodedDictionary(let signature, let decoded) = event {
      recordWireSignature(signature, channel: .reply)
      handle(decoded, operation: operation)
      return
    }
    guard
      (operation == .startConnection && phase == .starting)
        || (operation == .stopConnection && phase == .stopping)
    else { return }
    switch event {
    case .decodedDictionary:
      return
    case .ncRouteToggleAcknowledgement:
      finishReply(.unexpectedReplyPayload, operation)
    case .emptyAcknowledgement:
      acceptEmptyAcknowledgement(for: operation)
    case .connectionInterrupted: finishReply(.connectionInterrupted, operation)
    case .connectionInvalid: finishReply(.connectionInvalid, operation)
    case .peerCodeSigningRequirement: finishReply(.peerCodeSigningRequirement, operation)
    case .unexpectedXPCError: finishReply(.unexpectedXPCError, operation)
    case .unexpectedPayload: finishReply(.unexpectedReplyPayload, operation)
    }
  }

  private func acceptEmptyAcknowledgement(
    for operation: VendorCharonControlOperation
  ) {
    emptyReplyObserved = true
    if operation == .startConnection {
      beginPeerGenerationValidation()
    } else {
      finishStop(.transportAcknowledged, retainConnection: false)
    }
  }

  private func finishReply(
    _ outcome: VendorCharonControlOutcome,
    _ operation: VendorCharonControlOperation
  ) {
    if operation == .startConnection {
      finishStart(
        outcome,
        sealSubmittedSession: outcome != .unexpectedReplyPayload
      )
    } else {
      finishStop(outcome, retainConnection: false)
    }
  }

  func handle(_ event: VendorCharonControlConnectionEvent) {
    switch event {
    case .decodedDictionary(let signature, let decoded):
      recordWireSignature(signature, channel: .connection)
      if phase == .starting {
        switch decoded {
        case .unexpectedDictionary, .unexpectedConnectionEvent:
          startUnexpectedEventSignature = signature
        default:
          break
        }
      }
      handle(decoded)
    case .status(let signal):
      updateObservation {
        if statusEvents < Int.max { statusEvents += 1 }
        latestStatus = signal
      }
      handleStatusWait(signal.classification)
    case .tunnelNameReported:
      break
    case .emptyDispatcherTail:
      updateObservation {
        if dispatcherTailEvents < Int.max { dispatcherTailEvents += 1 }
      }
      // The helper uses an ordinary send at 0x1001ac379-0x1001ac38e.
      // Attempt 6 observed `1:connection:{}` and no reply-channel message.
      guard requestSent else { return }
      if phase == .starting {
        acceptEmptyAcknowledgement(for: .startConnection)
      } else if phase == .stopping {
        acceptEmptyAcknowledgement(for: .stopConnection)
      }
    case .unexpectedDictionary:
      updateObservation {
        if unexpectedDictionaryEvents < Int.max { unexpectedDictionaryEvents += 1 }
      }
      finishPending(.unexpectedConnectionEvent)
    case .connectionInterrupted: finishPending(.connectionInterrupted)
    case .connectionInvalid: finishPending(.connectionInvalid)
    case .peerCodeSigningRequirement: finishPending(.peerCodeSigningRequirement)
    case .unexpectedXPCError: finishPending(.unexpectedXPCError)
    case .unexpectedConnectionEvent: finishPending(.unexpectedConnectionEvent)
    }
  }

  private func recordWireSignature(
    _ signature: [String],
    channel: VendorCharonWireSignatureChannel
  ) {
    let description = VendorCharonControlWireCodec.signatureDescription(signature)
    let fingerprint = "\(channel.rawValue):\(description)"
    updateObservation {
      guard lastWireSignatureFingerprint != fingerprint else { return }
      lastWireSignatureFingerprint = fingerprint
      if wireSignatureSequence < Int.max { wireSignatureSequence += 1 }
      let entry = "\(wireSignatureSequence):\(fingerprint)"
      switch channel {
      case .connection where incomingEventSignatures.count < 12:
        incomingEventSignatures.append(entry)
      case .reply where replySignatures.count < 4:
        replySignatures.append(entry)
      default:
        break
      }
    }
  }

  func recordReplyWireSignature(_ signature: [String]) {
    recordWireSignature(signature, channel: .reply)
  }

  private func finishPending(_ outcome: VendorCharonControlOutcome) {
    updateObservation { terminalConnectionOutcome = outcome }
    finishStatusWait(.terminalError)
    if phase == .starting {
      finishStart(outcome, sealSubmittedSession: true)
    } else if phase == .stopping {
      finishStop(outcome, retainConnection: false)
    } else if phase == .togglingNC, let attempt = activeNCRouteToggleAttempt {
      finishNCRouteToggle(outcome, retainConnection: false, attempt: attempt)
    } else if phase == .active {
      _ = cancelDriver()
      phase = .closed
    } else if phase == .provisional {
      _ = cancelDriver()
      phase = .closed
    }
  }
}
