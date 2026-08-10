import Dispatch
import Foundation

extension RawVendorCharonControlTransport {
  /// Sends only the fixed charon `stop_connection` request.
  ///
  /// `expectedRunningPredicate` is evaluated synchronously before a driver is
  /// created. Product must bind it to one previously cold-started generation.
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
      driverFactory: driverFactory,
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
  private enum Phase { case idle, pending, closed }

  private let queue = DispatchQueue(label: "com.powervpn.vendor-charon-emergency-stop")
  private let driverFactory: RawVendorCharonControlTransport.DriverFactory
  private let peerGenerationValidator: @Sendable (Int32) -> Bool
  private var phase = Phase.idle
  private var driver: (any VendorCharonControlConnectionDriving)?
  private var timer: DispatchSourceTimer?
  private var continuation: CheckedContinuation<VendorCharonControlReceipt, Never>?
  private var completedReceipt: VendorCharonControlReceipt?
  private var requestSent = false
  private var emptyReplyObserved = false
  private var statusEventCount = 0
  private var dispatcherTailEventCount = 0
  private var cancelIssued = false

  init(
    driverFactory: @escaping RawVendorCharonControlTransport.DriverFactory,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) {
    self.driverFactory = driverFactory
    self.peerGenerationValidator = peerGenerationValidator
  }

  func beginSynchronously(timeoutMilliseconds: Int) {
    queue.sync {
      guard phase == .idle else { return }
      phase = .pending
      let driver = driverFactory(queue) { [weak self] event in
        guard let self else { return }
        self.queue.async { self.handle(event) }
      }
      self.driver = driver
      armTimeout(milliseconds: timeoutMilliseconds)
      requestSent = true
      driver.submit(VendorCharonControlWireCodec.makeStopRequest()) { [weak self] event in
        guard let self else { return }
        self.queue.async { self.handle(event) }
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
    queue.async { [self] in finish(.cancelled) }
  }

  private func handle(_ event: VendorCharonControlReplyEvent) {
    guard phase == .pending else { return }
    switch event {
    case .emptyAcknowledgement(let peerPID):
      emptyReplyObserved = true
      finish(
        peerGenerationValidator(peerPID)
          ? .transportAcknowledged : .peerGenerationMismatch
      )
    case .connectionInterrupted: finish(.connectionInterrupted)
    case .connectionInvalid: finish(.connectionInvalid)
    case .peerCodeSigningRequirement: finish(.peerCodeSigningRequirement)
    case .unexpectedXPCError: finish(.unexpectedXPCError)
    case .unexpectedPayload: finish(.unexpectedReplyPayload)
    }
  }

  private func handle(_ event: VendorCharonControlConnectionEvent) {
    guard phase == .pending else { return }
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
    guard phase == .pending else { return }
    phase = .closed
    timer?.cancel()
    timer = nil
    let cancelled = cancelDriver()
    let receipt = VendorCharonControlReceipt(
      operation: .stopConnection,
      outcome: outcome,
      requestSent: requestSent,
      emptyReplyObserved: emptyReplyObserved,
      peerGenerationValidated: outcome == .transportAcknowledged,
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
