import Dispatch
import Foundation

extension RawVendorCharonControlTransport {
  /// Authenticates the expected running helper with exact `get_version`, then
  /// sends exact `stop_connection` over that same fixed-service connection.
  package func emergencyStop(
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    expectedRunningPredicate: @escaping @Sendable () -> Bool,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) async -> VendorCharonControlReceipt {
    guard Self.validTimeoutMilliseconds.contains(timeoutMilliseconds) else {
      return Self.unsentEmergencyStop(.invalidTimeout)
    }
    guard !Task.isCancelled else {
      return Self.unsentEmergencyStop(.cancelled)
    }
    guard expectedRunningPredicate() else {
      return Self.unsentEmergencyStop(.preflightBlocked)
    }

    let transaction = VendorCharonEmergencyStopTransaction(
      driverFactory: emergencyDriverFactory,
      peerGenerationValidator: peerGenerationValidator
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
  private enum Phase { case idle, probing, stopping, closed }

  private let queue = DispatchQueue(label: "com.powervpn.vendor-charon-emergency-stop")
  private let driverFactory: RawVendorCharonControlTransport.EmergencyDriverFactory
  private let peerGenerationValidator: @Sendable (Int32) -> Bool
  private var phase = Phase.idle
  private var driver: (any VendorCharonEmergencyConnectionDriving)?
  private var timer: DispatchSourceTimer?
  private var continuation: CheckedContinuation<VendorCharonControlReceipt, Never>?
  private var completedReceipt: VendorCharonControlReceipt?
  private var stopRequestSent = false
  private var emptyStopReplyObserved = false
  private var probeBusinessValidated = false
  private var probeEmptyReplyObserved = false
  /// Retained only inside this transaction; never serialized or reported.
  private var authenticatedPeerPID: Int32?
  private var peerGenerationValidated = false
  private var statusEventCount = 0
  private var dispatcherTailEventCount = 0
  private var cancelIssued = false

  init(
    driverFactory: @escaping RawVendorCharonControlTransport.EmergencyDriverFactory,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) {
    self.driverFactory = driverFactory
    self.peerGenerationValidator = peerGenerationValidator
  }

  func beginSynchronously(timeoutMilliseconds: Int) {
    queue.sync {
      guard phase == .idle else { return }
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
      armTimeout(milliseconds: timeoutMilliseconds)
      driver.beginProbe(VendorXPCWireCodec.makeGetVersionRequest())
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
    queue.async { [self] in finish(.cancelled) }
  }

  private func handleProbe(_ event: VendorXPCConnectionEvent) {
    guard phase == .probing else { return }
    switch event {
    case .business(let reply, let peerPID):
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
      guard peerPID > 0, peerGenerationValidator(peerPID) else {
        finish(.peerGenerationMismatch)
        return
      }
      probeBusinessValidated = true
      authenticatedPeerPID = peerPID
      peerGenerationValidated = true
      beginStopIfProbeComplete()
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
      let driver,
      let authenticatedPeerPID
    else { return }
    phase = .stopping
    let submitted = driver.submitStop(
      VendorCharonControlWireCodec.makeStopRequest(),
      expectedPeerPID: authenticatedPeerPID
    ) { [weak self] event in
      guard let self else { return }
      self.queue.async { self.handleStopReply(event) }
    }
    guard submitted else {
      peerGenerationValidated = false
      finish(.peerGenerationMismatch)
      return
    }
    stopRequestSent = true
  }

  private func handleStopReply(_ event: VendorCharonControlReplyEvent) {
    guard phase == .stopping else { return }
    switch event {
    case .emptyAcknowledgement(let peerPID):
      emptyStopReplyObserved = true
      guard peerPID > 0, peerPID == authenticatedPeerPID else {
        peerGenerationValidated = false
        finish(.peerGenerationMismatch)
        return
      }
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
    let cancelled = cancelDriver()
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

  private func cancelDriver() -> Bool {
    guard !cancelIssued, let driver else { return false }
    cancelIssued = true
    self.driver = nil
    driver.cancel()
    return true
  }
}
