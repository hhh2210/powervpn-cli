import Dispatch
import Foundation

extension RawVendorCharonControlTransport {
  package func emergencyStop(
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    stopContext: VendorCharonStopContext,
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> VendorCharonControlReceipt {
    await emergencyStop(
      timeoutMilliseconds: timeoutMilliseconds,
      stopContext: stopContext,
      expectedRunningPredicate: expectedRunningPredicate,
      peerGenerationValidator: peerGenerationValidator,
      postStopDrainScheduler: VendorCharonControlConnectionDrain.productionScheduler
    )
  }

  func emergencyStop(
    timeoutMilliseconds: Int,
    stopContext: VendorCharonStopContext,
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    postStopDrainScheduler: @escaping VendorCharonConnectionDrainScheduler
  ) async -> VendorCharonControlReceipt {
    guard Self.validTimeoutMilliseconds.contains(timeoutMilliseconds) else {
      return Self.unsentEmergencyStop(.invalidTimeout)
    }
    guard !Task.isCancelled else {
      return Self.unsentEmergencyStop(.cancelled)
    }
    let transaction = VendorCharonEmergencyStopTransaction(
      driverFactory: emergencyDriverFactory,
      stopContext: stopContext,
      expectedRunningPredicate: expectedRunningPredicate,
      peerGenerationValidator: peerGenerationValidator,
      postStopDrainScheduler: postStopDrainScheduler
    )
    transaction.beginSynchronously(timeoutMilliseconds: timeoutMilliseconds)
    return await transaction.result()
  }

  private static func unsentEmergencyStop(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonControlReceipt {
    VendorCharonControlReceipt(
      operation: .stopConnection,
      outcome: outcome,
      requestSent: false,
      emptyReplyObserved: false,
      peerGenerationValidated: false,
      connectionRetained: false,
      connectionCancelRequested: false,
      encodingError: nil,
      statusEventCount: 0,
      dispatcherTailEventCount: 0
    )
  }
}

private final class VendorCharonEmergencyStopTransaction: @unchecked Sendable {
  private enum Phase { case idle, preflighting, probing, stopping, closed }

  private let queue = DispatchQueue(label: "com.powervpn.vendor-charon-emergency-stop")
  private let driverFactory: RawVendorCharonControlTransport.EmergencyDriverFactory
  private let stopContext: VendorCharonStopContext
  private let expectedRunningPredicate: @Sendable () async -> Bool
  private let peerGenerationValidator: @Sendable () async -> Bool
  private let postStopDrainScheduler: VendorCharonConnectionDrainScheduler
  private var phase = Phase.idle
  private var driver: (any VendorCharonEmergencyConnectionDriving)?
  private var postStopDrain: VendorCharonControlConnectionDrain?
  private var timer: DispatchSourceTimer?
  private var continuation: CheckedContinuation<VendorCharonControlReceipt, Never>?
  private var completedReceipt: VendorCharonControlReceipt?
  private var stopRequestSent = false
  private var emptyStopReplyObserved = false
  private var probeBusinessValidated = false
  private var probeEmptyReplyObserved = false
  private var peerGenerationValidated = false
  private var statusEventCount = 0
  private var dispatcherTailEventCount = 0
  private var cancelIssued = false
  private var validation: VendorCharonAsyncValidation?

  init(
    driverFactory: @escaping RawVendorCharonControlTransport.EmergencyDriverFactory,
    stopContext: VendorCharonStopContext,
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    postStopDrainScheduler: @escaping VendorCharonConnectionDrainScheduler
  ) {
    self.driverFactory = driverFactory
    self.stopContext = stopContext
    self.expectedRunningPredicate = expectedRunningPredicate
    self.peerGenerationValidator = peerGenerationValidator
    self.postStopDrainScheduler = postStopDrainScheduler
  }

  func beginSynchronously(timeoutMilliseconds: Int) {
    queue.sync {
      guard phase == .idle else { return }
      phase = .preflighting
      armTimeout(milliseconds: timeoutMilliseconds)
      beginValidation(expectedRunningPredicate) { transaction, accepted in
        transaction.completePreflight(accepted)
      }
    }
  }

  func result() async -> VendorCharonControlReceipt {
    if Task.isCancelled { cancel() }
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        queue.async { [self] in
          if let completedReceipt {
            self.completedReceipt = nil
            continuation.resume(returning: completedReceipt)
          } else {
            self.continuation = continuation
          }
        }
      }
    } onCancel: {
      self.cancel()
    }
  }

  private func armTimeout(milliseconds: Int) {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + .milliseconds(milliseconds))
    timer.setEventHandler { [self] in finish(.timeout) }
    self.timer = timer
    timer.resume()
  }

  private func cancel() {
    queue.async { [self] in
      if phase == .closed {
        _ = cancelDriver()
      } else {
        finish(.cancelled)
      }
    }
  }

  private func completePreflight(_ accepted: Bool) {
    guard phase == .preflighting else { return }
    guard accepted else {
      finish(.preflightBlocked)
      return
    }
    phase = .probing
    let driver = driverFactory(
      queue,
      { [weak self] event in
        guard let self else { return }
        self.queue.async { self.handleProbe(event) }
      },
      { [weak self] event in
        guard let self else { return }
        self.queue.async { self.handleProbeReply(event) }
      },
      { [weak self] event in
        guard let self else { return }
        self.queue.async { self.handleStopEvent(event) }
      }
    )
    self.driver = driver
    let submission = driver.beginProbe(VendorXPCWireCodec.makeGetVersionRequest())
    if case .rejected(let outcome) = submission { finish(outcome) }
  }

  private func handleProbe(_ event: VendorCharonEmergencyProbeEvent) {
    guard phase == .probing else { return }
    switch event {
    case .business(let reply):
      guard !probeBusinessValidated else {
        finish(.unexpectedConnectionEvent)
        return
      }
      guard reply.versionMatchesLockedBuild else {
        finish(.helperVersionMismatch)
        return
      }
      guard reply.getVersionSuccess else {
        finish(.helperVersionRejected)
        return
      }
      probeBusinessValidated = true
      beginValidation(peerGenerationValidator) { transaction, accepted in
        transaction.completePeerGenerationValidation(accepted)
      }
    case .emptyDispatcherTail:
      if dispatcherTailEventCount < Int.max { dispatcherTailEventCount += 1 }
    case .malformedBusinessEvent: finish(.unexpectedConnectionEvent)
    case .connectionInterrupted: finish(.connectionInterrupted)
    case .connectionInvalid: finish(.connectionInvalid)
    case .peerCodeSigningRequirement: finish(.peerCodeSigningRequirement)
    case .unexpectedXPCError: finish(.unexpectedXPCError)
    case .unexpectedConnectionEvent: finish(.unexpectedConnectionEvent)
    }
  }

  private func handleProbeReply(_ event: VendorXPCReplyCallbackEvent) {
    guard phase == .probing else { return }
    switch event {
    case .emptyAcknowledgement:
      probeEmptyReplyObserved = true
      beginStopIfProbeComplete()
    case .connectionInterrupted: finish(.connectionInterrupted)
    case .connectionInvalid: finish(.connectionInvalid)
    case .peerCodeSigningRequirement: finish(.peerCodeSigningRequirement)
    case .unexpectedXPCError: finish(.unexpectedXPCError)
    case .unexpectedPayload: finish(.unexpectedReplyPayload)
    }
  }

  private func beginStopIfProbeComplete() {
    guard phase == .probing,
      probeBusinessValidated,
      probeEmptyReplyObserved,
      peerGenerationValidated,
      let driver
    else { return }
    phase = .stopping
    let submission = driver.submitStop(
      VendorCharonControlWireCodec.makeStopRequest(context: stopContext)
    ) { [weak self] event in
      guard let self else { return }
      self.queue.async { self.handleStopReply(event) }
    }
    guard case .submitted = submission else {
      if case .rejected(let outcome) = submission { finish(outcome) }
      return
    }
    stopRequestSent = true
  }

  private func handleStopReply(_ event: VendorCharonControlReplyEvent) {
    guard phase == .stopping else { return }
    switch event {
    case .emptyAcknowledgement:
      emptyStopReplyObserved = true
      finish(.transportAcknowledged)
    case .connectionInterrupted: finish(.connectionInterrupted)
    case .connectionInvalid: finish(.connectionInvalid)
    case .peerCodeSigningRequirement: finish(.peerCodeSigningRequirement)
    case .unexpectedXPCError: finish(.unexpectedXPCError)
    case .unexpectedPayload: finish(.unexpectedReplyPayload)
    }
  }

  private func handleStopEvent(_ event: VendorCharonControlConnectionEvent) {
    guard phase == .stopping else { return }
    switch event {
    case .status:
      if statusEventCount < Int.max { statusEventCount += 1 }
    case .tunnelNameReported:
      break
    case .emptyDispatcherTail:
      if dispatcherTailEventCount < Int.max { dispatcherTailEventCount += 1 }
    case .unexpectedDictionary: finish(.unexpectedConnectionEvent)
    case .connectionInterrupted: finish(.connectionInterrupted)
    case .connectionInvalid: finish(.connectionInvalid)
    case .peerCodeSigningRequirement: finish(.peerCodeSigningRequirement)
    case .unexpectedXPCError: finish(.unexpectedXPCError)
    case .unexpectedConnectionEvent: finish(.unexpectedConnectionEvent)
    }
  }

  private func finish(_ outcome: VendorCharonControlOutcome) {
    guard phase != .idle, phase != .closed else { return }
    phase = .closed
    timer?.cancel()
    timer = nil
    validation?.cancel()
    validation = nil
    let cancelled: Bool
    if outcome == .transportAcknowledged {
      armPostStopDrain()
      cancelled = false
    } else {
      cancelled = cancelDriver()
    }
    let receipt = VendorCharonControlReceipt(
      operation: .stopConnection,
      outcome: outcome,
      requestSent: stopRequestSent,
      emptyReplyObserved: emptyStopReplyObserved,
      peerGenerationValidated: peerGenerationValidated,
      connectionRetained: false,
      connectionCancelRequested: cancelled,
      encodingError: nil,
      statusEventCount: statusEventCount,
      dispatcherTailEventCount: dispatcherTailEventCount
    )
    if let continuation {
      self.continuation = nil
      continuation.resume(returning: receipt)
    } else {
      completedReceipt = receipt
    }
  }

  private func armPostStopDrain() {
    guard let driver else { return }
    self.driver = nil
    let drain = VendorCharonControlConnectionDrain(
      cancelDriver: { driver.cancel() },
      scheduler: postStopDrainScheduler
    )
    postStopDrain = drain
    drain.arm(on: queue)
  }

  private func cancelDriver() -> Bool {
    if let drain = postStopDrain {
      postStopDrain = nil
      return drain.cancelNow()
    }
    guard !cancelIssued, let driver else { return false }
    cancelIssued = true
    self.driver = nil
    driver.cancel()
    return true
  }

  private func completePeerGenerationValidation(_ accepted: Bool) {
    guard phase == .probing else { return }
    guard accepted else {
      finish(.peerGenerationMismatch)
      return
    }
    peerGenerationValidated = true
    beginStopIfProbeComplete()
  }

  private func beginValidation(
    _ operation: @escaping @Sendable () async -> Bool,
    completion: @escaping @Sendable (VendorCharonEmergencyStopTransaction, Bool) -> Void
  ) {
    validation = VendorCharonAsyncValidation(operation: operation) { [weak self] accepted in
      guard let self else { return }
      self.queue.async { [weak self] in
        guard let self, phase != .closed else { return }
        validation = nil
        completion(self, accepted)
      }
    }
  }
}
