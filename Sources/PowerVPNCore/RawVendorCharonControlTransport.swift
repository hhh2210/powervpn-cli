import Dispatch
import Foundation

package struct RawVendorCharonControlTransport: Sendable {
  package static let defaultTimeoutMilliseconds = 2_000
  package static let validTimeoutMilliseconds = 1...60_000

  typealias DriverFactory =
    @Sendable (
      DispatchQueue,
      @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
    ) -> any VendorCharonControlConnectionDriving

  private let driverFactory: DriverFactory

  package init() {
    driverFactory = { queue, handler in
      SystemVendorCharonControlConnectionDriver(
        queue: queue,
        connectionEventHandler: handler
      )
    }
  }

  init(driverFactory: @escaping DriverFactory) {
    self.driverFactory = driverFactory
  }

  package func beginStart(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) -> VendorCharonPendingStart {
    guard Self.validTimeoutMilliseconds.contains(timeoutMilliseconds) else {
      return VendorCharonPendingStart(immediate: immediateStartResult(.invalidTimeout))
    }
    guard !Task.isCancelled else {
      return VendorCharonPendingStart(immediate: immediateStartResult(.cancelled))
    }

    let state = VendorCharonControlState(
      snapshot: snapshot,
      driverFactory: driverFactory
    )
    state.beginStartSynchronously(
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator
    )
    return VendorCharonPendingStart(state: state)
  }

  package func start(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) async -> VendorCharonStartControlResult {
    await beginStart(
      snapshot: snapshot,
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator
    ).result()
  }

  private func immediateStartResult(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonStartControlResult {
    VendorCharonStartControlResult(
      receipt: VendorCharonControlReceipt(
        operation: .startConnection,
        outcome: outcome,
        requestSent: false,
        emptyReplyObserved: false,
        peerGenerationValidated: false,
        connectionRetained: false,
        connectionCancelRequested: false,
        encodingError: nil,
        statusEventCount: 0,
        dispatcherTailEventCount: 0
      ),
      lease: nil
    )
  }
}

package final class VendorCharonPendingStart: @unchecked Sendable {
  private let lock = NSLock()
  private let state: VendorCharonControlState?
  private let immediate: VendorCharonStartControlResult?
  private var consumed = false

  init(state: VendorCharonControlState) {
    self.state = state
    immediate = nil
  }

  init(immediate: VendorCharonStartControlResult) {
    state = nil
    self.immediate = immediate
  }

  deinit {
    state?.discardPendingStart()
  }

  package func result() async -> VendorCharonStartControlResult {
    let first = lock.withLock {
      guard !consumed else { return false }
      consumed = true
      return true
    }
    guard first else {
      return VendorCharonStartControlResult(
        receipt: VendorCharonControlReceipt(
          operation: .startConnection,
          outcome: .leaseClosed,
          requestSent: false,
          emptyReplyObserved: false,
          peerGenerationValidated: false,
          connectionRetained: false,
          connectionCancelRequested: false,
          encodingError: nil,
          statusEventCount: 0,
          dispatcherTailEventCount: 0
        ),
        lease: nil
      )
    }
    if let immediate { return immediate }
    guard let state else {
      return VendorCharonStartControlResult(
        receipt: VendorCharonControlReceipt(
          operation: .startConnection,
          outcome: .leaseClosed,
          requestSent: false,
          emptyReplyObserved: false,
          peerGenerationValidated: false,
          connectionRetained: false,
          connectionCancelRequested: false,
          encodingError: nil,
          statusEventCount: 0,
          dispatcherTailEventCount: 0
        ),
        lease: nil
      )
    }
    return await state.awaitStartResult()
  }
}
