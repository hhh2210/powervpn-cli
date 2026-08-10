import Dispatch
import Foundation

package enum VendorCharonStatusWaitOutcome: String, Equatable, Sendable {
  case connected
  case disconnected
  case timeout
  case cancelled
  case leaseClosed = "lease_closed"
  case terminalError = "terminal_error"
}

/// Value-free terminal result for one bounded wait on the retained XPC session.
package struct VendorCharonStatusWaitResult: Equatable, Sendable {
  package let outcome: VendorCharonStatusWaitOutcome
  package let statusEventCount: Int
  package let latestClassification: VendorCharonStatusClassification?
  package let terminalOutcome: VendorCharonControlOutcome?
}

final class VendorCharonStatusWaitAttempt: @unchecked Sendable {
  private let lock = NSLock()
  private var cancelled = false

  var isCancelled: Bool { lock.withLock { cancelled } }

  func cancel() {
    lock.withLock { cancelled = true }
  }
}

extension VendorCharonControlState {
  var statusWaitPending: Bool {
    queue.sync { statusWaitContinuation != nil }
  }

  func waitForConnectedStatus(
    timeoutMilliseconds: Int
  ) async -> VendorCharonStatusWaitResult {
    guard RawVendorCharonControlTransport.validTimeoutMilliseconds.contains(timeoutMilliseconds)
    else { return await immediateStatusWait(.terminalError, terminal: .invalidTimeout) }
    guard !Task.isCancelled else { return await immediateStatusWait(.cancelled) }

    let attempt = VendorCharonStatusWaitAttempt()
    let deadline = DispatchTime.now() + .milliseconds(timeoutMilliseconds)
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        queue.async { [self] in
          if phase != .active {
            let outcome: VendorCharonStatusWaitOutcome =
              observation.terminalConnectionOutcome == nil ? .leaseClosed : .terminalError
            continuation.resume(returning: makeStatusWaitResult(outcome))
            return
          }
          if let outcome = latestTerminalStatus?.waitOutcome {
            continuation.resume(returning: makeStatusWaitResult(outcome))
            return
          }
          guard statusWaitContinuation == nil else {
            continuation.resume(returning: makeStatusWaitResult(.leaseClosed))
            return
          }
          guard !attempt.isCancelled else {
            continuation.resume(returning: makeStatusWaitResult(.cancelled))
            return
          }
          currentStatusWaitAttempt = attempt
          statusWaitContinuation = continuation
          armStatusWaitTimer(deadline: deadline, attempt: attempt)
        }
      }
    } onCancel: {
      attempt.cancel()
      self.queue.async { [self] in
        guard currentStatusWaitAttempt === attempt else { return }
        finishStatusWait(.cancelled)
      }
    }
  }

  func handleStatusWait(_ classification: VendorCharonStatusClassification) {
    guard let outcome = classification.waitOutcome else { return }
    latestTerminalStatus = classification
    finishStatusWait(outcome)
  }

  func finishStatusWait(_ outcome: VendorCharonStatusWaitOutcome) {
    guard let continuation = statusWaitContinuation else { return }
    statusWaitTimer?.cancel()
    statusWaitTimer = nil
    currentStatusWaitAttempt = nil
    statusWaitContinuation = nil
    continuation.resume(returning: makeStatusWaitResult(outcome))
  }

  private func armStatusWaitTimer(
    deadline: DispatchTime,
    attempt: VendorCharonStatusWaitAttempt
  ) {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: deadline)
    timer.setEventHandler { [self] in
      guard currentStatusWaitAttempt === attempt else { return }
      finishStatusWait(.timeout)
    }
    statusWaitTimer = timer
    timer.resume()
  }

  private func immediateStatusWait(
    _ outcome: VendorCharonStatusWaitOutcome,
    terminal: VendorCharonControlOutcome? = nil
  ) async -> VendorCharonStatusWaitResult {
    await withCheckedContinuation { continuation in
      queue.async { [self] in
        continuation.resume(returning: makeStatusWaitResult(outcome, terminal: terminal))
      }
    }
  }

  private func makeStatusWaitResult(
    _ outcome: VendorCharonStatusWaitOutcome,
    terminal: VendorCharonControlOutcome? = nil
  ) -> VendorCharonStatusWaitResult {
    let current = observation
    return VendorCharonStatusWaitResult(
      outcome: outcome,
      statusEventCount: current.statusEventCount,
      latestClassification: current.latestStatus?.classification,
      terminalOutcome: terminal ?? current.terminalConnectionOutcome
    )
  }
}

extension VendorCharonStatusClassification {
  fileprivate var waitOutcome: VendorCharonStatusWaitOutcome? {
    switch self {
    case .connected: .connected
    case .disconnected: .disconnected
    case .unclassified: nil
    }
  }
}
