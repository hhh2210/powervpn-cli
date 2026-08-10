import Dispatch
import Foundation

final class VendorCharonControlState: @unchecked Sendable {
  enum Phase { case idle, starting, active, stopping, closed }

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
  var snapshot: VendorCharonStartSnapshot?
  var driver: (any VendorCharonControlConnectionDriving)?
  var phase = Phase.idle
  var timer: DispatchSourceTimer?
  var startContinuation: CheckedContinuation<VendorCharonStartControlResult, Never>?
  var completedStartResult: VendorCharonStartControlResult?
  var stopContinuation: CheckedContinuation<VendorCharonControlReceipt, Never>?
  var currentStopAttempt: StopAttempt?
  var currentValidator: (@Sendable (Int32) -> Bool)?
  var requestSent = false
  var emptyReplyObserved = false
  var statusEvents = 0
  var latestStatus: VendorCharonStatusSignal?
  var dispatcherTailEvents = 0
  var unexpectedDictionaryEvents = 0
  var terminalConnectionOutcome: VendorCharonControlOutcome?
  var cancelIssued = false

  init(
    snapshot: VendorCharonStartSnapshot,
    driverFactory: @escaping RawVendorCharonControlTransport.DriverFactory
  ) {
    self.snapshot = snapshot
    self.driverFactory = driverFactory
  }

  var observation: VendorCharonControlObservation {
    observationLock.withLock {
      VendorCharonControlObservation(
        statusEventCount: statusEvents,
        latestStatus: latestStatus,
        dispatcherTailEventCount: dispatcherTailEvents,
        unexpectedDictionaryEventCount: unexpectedDictionaryEvents,
        terminalConnectionOutcome: terminalConnectionOutcome
      )
    }
  }

  func beginStartSynchronously(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) {
    queue.sync {
      beginStart(
        timeoutMilliseconds: timeoutMilliseconds,
        peerGenerationValidator: peerGenerationValidator
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

  func stop(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
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
          currentStopAttempt = attempt
          stopContinuation = continuation
          beginStop(
            timeoutMilliseconds: timeoutMilliseconds,
            peerGenerationValidator: peerGenerationValidator
          )
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

  func abandon() {
    queue.async { [self] in
      guard phase == .active else { return }
      _ = cancelDriver()
      phase = .closed
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
    }
  }

  private func cancelPendingStartWait() {
    queue.async { [self] in
      if phase == .starting { finishStart(.cancelled) }
    }
  }

  private func beginStart(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) {
    guard phase == .idle, let snapshot else {
      finishStart(.leaseClosed)
      return
    }
    phase = .starting
    currentValidator = peerGenerationValidator
    defer { self.snapshot = nil }
    do {
      try snapshot.withEncodedStartMessage { request in
        let driver = driverFactory(queue) { [weak self] event in
          guard let self else { return }
          self.queue.async { self.handle(event) }
        }
        self.driver = driver
        armTimeout(milliseconds: timeoutMilliseconds, operation: .startConnection)
        requestSent = true
        driver.submit(request) { [weak self] event in
          guard let self else { return }
          self.queue.async { self.handle(event, operation: .startConnection) }
        }
      }
    } catch let error as VendorCharonStartEncodingError {
      finishStart(.snapshotEncodingFailed, encodingError: error)
    } catch {
      finishStart(.snapshotEncodingFailed)
    }
  }

  private func beginStop(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) {
    guard phase == .active, let driver else {
      finishStop(.leaseClosed, retainConnection: false)
      return
    }
    phase = .stopping
    currentValidator = peerGenerationValidator
    requestSent = true
    emptyReplyObserved = false
    armTimeout(milliseconds: timeoutMilliseconds, operation: .stopConnection)
    driver.submit(VendorCharonControlWireCodec.makeStopRequest()) { [weak self] event in
      guard let self else { return }
      self.queue.async { self.handle(event, operation: .stopConnection) }
    }
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
    guard
      (operation == .startConnection && phase == .starting)
        || (operation == .stopConnection && phase == .stopping)
    else { return }
    let outcome: VendorCharonControlOutcome
    switch event {
    case .emptyAcknowledgement(let peerPID):
      emptyReplyObserved = true
      outcome =
        currentValidator?(peerPID) == true
        ? .transportAcknowledged : .peerGenerationMismatch
    case .connectionInterrupted: outcome = .connectionInterrupted
    case .connectionInvalid: outcome = .connectionInvalid
    case .peerCodeSigningRequirement: outcome = .peerCodeSigningRequirement
    case .unexpectedXPCError: outcome = .unexpectedXPCError
    case .unexpectedPayload: outcome = .unexpectedReplyPayload
    }
    if operation == .startConnection {
      finishStart(outcome)
    } else {
      finishStop(outcome, retainConnection: false)
    }
  }

  private func handle(_ event: VendorCharonControlConnectionEvent) {
    switch event {
    case .status(let signal):
      updateObservation {
        if statusEvents < Int.max { statusEvents += 1 }
        latestStatus = signal
      }
    case .emptyDispatcherTail:
      updateObservation {
        if dispatcherTailEvents < Int.max { dispatcherTailEvents += 1 }
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

  private func finishPending(_ outcome: VendorCharonControlOutcome) {
    updateObservation { terminalConnectionOutcome = outcome }
    if phase == .starting {
      finishStart(outcome)
    } else if phase == .stopping {
      finishStop(outcome, retainConnection: false)
    } else if phase == .active {
      _ = cancelDriver()
      phase = .closed
    }
  }
}
