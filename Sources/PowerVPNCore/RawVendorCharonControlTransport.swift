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

  typealias EmergencyDriverFactory =
    @Sendable (
      DispatchQueue,
      @escaping @Sendable (VendorCharonEmergencyProbeEvent) -> Void,
      @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void,
      @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
    ) -> any VendorCharonEmergencyConnectionDriving

  let driverFactory: DriverFactory
  let emergencyDriverFactory: EmergencyDriverFactory

  package init() {
    driverFactory = { queue, handler in
      SystemVendorCharonControlConnectionDriver(
        queue: queue,
        connectionEventHandler: handler
      )
    }
    emergencyDriverFactory = { queue, probeHandler, probeReplyHandler, stopHandler in
      SystemVendorCharonEmergencyConnectionDriver(
        queue: queue,
        probeEventHandler: probeHandler,
        probeReplyHandler: probeReplyHandler,
        stopEventHandler: stopHandler
      )
    }
  }

  init(driverFactory: @escaping DriverFactory) {
    self.driverFactory = driverFactory
    emergencyDriverFactory = { queue, probeHandler, probeReplyHandler, stopHandler in
      SystemVendorCharonEmergencyConnectionDriver(
        queue: queue,
        probeEventHandler: probeHandler,
        probeReplyHandler: probeReplyHandler,
        stopEventHandler: stopHandler
      )
    }
  }

  init(
    driverFactory: @escaping DriverFactory,
    emergencyDriverFactory: @escaping EmergencyDriverFactory
  ) {
    self.driverFactory = driverFactory
    self.emergencyDriverFactory = emergencyDriverFactory
  }

  package func beginStart(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) -> VendorCharonPendingStart {
    if let rejection = startPreflightRejection(timeoutMilliseconds) { return rejection }
    return try! submitStart(
      snapshot: snapshot,
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator,
      commitStartAuthorization: {}
    )
  }

  package func beginStart(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    commitStartAuthorization: @Sendable () throws -> Void
  ) throws -> VendorCharonPendingStart {
    if let rejection = startPreflightRejection(timeoutMilliseconds) { return rejection }
    return try submitStart(
      snapshot: snapshot,
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator,
      commitStartAuthorization: commitStartAuthorization
    )
  }

  private func submitStart(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    commitStartAuthorization: @Sendable () throws -> Void
  ) throws -> VendorCharonPendingStart {
    let state = VendorCharonControlState(
      snapshot: snapshot,
      driverFactory: driverFactory
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator,
      commitStartAuthorization: commitStartAuthorization
    )
    return VendorCharonPendingStart(state: state)
  }

  private func startPreflightRejection(
    _ timeoutMilliseconds: Int
  ) -> VendorCharonPendingStart? {
    if !Self.validTimeoutMilliseconds.contains(timeoutMilliseconds) {
      return VendorCharonPendingStart(immediate: immediateStartResult(.invalidTimeout))
    }
    if Task.isCancelled {
      return VendorCharonPendingStart(immediate: immediateStartResult(.cancelled))
    }
    return nil
  }

  package func start(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
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
