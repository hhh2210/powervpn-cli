import Foundation

package enum VendorCharonControlOperation: String, Equatable, Sendable {
  case startConnection = "start_connection"
  case resourceToggleNC = "resource_toggle_nc"
  case stopConnection = "stop_connection"
}

package enum VendorCharonControlOutcome: String, Equatable, Sendable {
  case transportAcknowledged = "transport_acknowledged"
  case preflightBlocked = "preflight_blocked"
  case helperVersionMismatch = "helper_version_mismatch"
  case helperVersionRejected = "helper_version_rejected"
  case invalidTimeout = "invalid_timeout"
  case cancelled
  case timeout
  case snapshotEncodingFailed = "snapshot_encoding_failed"
  case peerGenerationMismatch = "peer_generation_mismatch"
  case connectionInterrupted = "connection_interrupted"
  case connectionInvalid = "connection_invalid"
  case peerCodeSigningRequirement = "peer_code_signing_requirement"
  case unexpectedXPCError = "unexpected_xpc_error"
  case unexpectedConnectionEvent = "unexpected_connection_event"
  case helperRejected = "helper_rejected"
  case unexpectedReplyPayload = "unexpected_reply_payload"
  case leaseClosed = "lease_closed"
}

/// Value-free evidence for one bounded helper-control request.
///
/// `requestSent` means the request was handed to libxpc. Start/stop use an
/// exact empty acknowledgement; `resourceToggleNC` uses an exact true boolean
/// reply. Neither acknowledgement proves tunnel routing or cleanup.
package struct VendorCharonControlReceipt: Equatable, Sendable {
  package let operation: VendorCharonControlOperation
  package let outcome: VendorCharonControlOutcome
  package let requestSent: Bool
  /// Legacy receipt slot populated by either empty acknowledgement channel.
  package let emptyReplyObserved: Bool
  package let peerGenerationValidated: Bool
  package let connectionRetained: Bool
  package let connectionCancelRequested: Bool
  package let encodingError: VendorCharonStartEncodingError?
  package let statusEventCount: Int
  package let dispatcherTailEventCount: Int
  /// Entries are `<ordinal>:<channel>:<sorted key:type...>`; values are absent.
  package let incomingEventSignatures: [String]
  package let replySignatures: [String]
  /// Exact key/type-only signature of the event that rejected start.
  package let unexpectedEventSignature: [String]?
  package var statusAtSubmission: VendorCharonStatusClassification? = nil
  package init(
    operation: VendorCharonControlOperation,
    outcome: VendorCharonControlOutcome,
    requestSent: Bool,
    emptyReplyObserved: Bool,
    peerGenerationValidated: Bool,
    connectionRetained: Bool,
    connectionCancelRequested: Bool,
    encodingError: VendorCharonStartEncodingError?,
    statusEventCount: Int,
    dispatcherTailEventCount: Int,
    incomingEventSignatures: [String] = [],
    replySignatures: [String] = [],
    unexpectedEventSignature: [String]? = nil,
    statusAtSubmission: VendorCharonStatusClassification? = nil
  ) {
    self.operation = operation
    self.outcome = outcome
    self.requestSent = requestSent
    self.emptyReplyObserved = emptyReplyObserved
    self.peerGenerationValidated = peerGenerationValidated
    self.connectionRetained = connectionRetained
    self.connectionCancelRequested = connectionCancelRequested
    self.encodingError = encodingError
    self.statusEventCount = statusEventCount
    self.dispatcherTailEventCount = dispatcherTailEventCount
    self.incomingEventSignatures = incomingEventSignatures
    self.replySignatures = replySignatures
    self.unexpectedEventSignature = unexpectedEventSignature
    self.statusAtSubmission = statusAtSubmission
  }

  package var transportAcknowledged: Bool {
    outcome == .transportAcknowledged
      && requestSent && peerGenerationValidated
      && (operation == .resourceToggleNC || emptyReplyObserved)
  }

  package var helperMayHaveMutated: Bool { requestSent }

  /// The route-toggle reply proves only that the helper accepted the request.
  package var helperSuccessEstablished: Bool {
    operation == .resourceToggleNC && transportAcknowledged
  }

  /// Transport acknowledgement alone cannot prove route/tunnel cleanup.
  package var cleanupEstablished: Bool { false }
}

package struct VendorCharonControlObservation: Equatable, Sendable {
  package let statusEventCount: Int
  package let latestStatus: VendorCharonStatusSignal?
  package let dispatcherTailEventCount: Int
  package let unexpectedDictionaryEventCount: Int
  package let incomingEventSignatures: [String]
  package let replySignatures: [String]
  package let terminalConnectionOutcome: VendorCharonControlOutcome?
}
package struct VendorCharonStopContext: Equatable, Sendable {
  let gatewayCString: [CChar]

  init?(gatewayCString: [CChar]) {
    guard !gatewayCString.isEmpty,
      gatewayCString.last == 0,
      !gatewayCString.dropLast().contains(0)
    else { return nil }
    self.gatewayCString = gatewayCString
  }

  init?(gateway: String) {
    var bytes = gateway.utf8.map { CChar(bitPattern: $0) }
    bytes.append(0)
    self.init(gatewayCString: bytes)
  }

  func withGatewayCString<Result>(
    _ body: (UnsafePointer<CChar>) throws -> Result
  ) rethrows -> Result {
    try gatewayCString.withUnsafeBufferPointer {
      try body($0.baseAddress!)
    }
  }
}

package struct VendorCharonStartControlResult: Sendable {
  package let receipt: VendorCharonControlReceipt
  package let lease: VendorCharonControlLease?
  package let provisionalStopCapability: VendorCharonProvisionalStopCapability?
  package let stopContext: VendorCharonStopContext?

  package init(
    receipt: VendorCharonControlReceipt,
    lease: VendorCharonControlLease?,
    provisionalStopCapability: VendorCharonProvisionalStopCapability? = nil,
    stopContext: VendorCharonStopContext? = nil
  ) {
    self.receipt = receipt
    self.lease = lease
    self.provisionalStopCapability = provisionalStopCapability
    self.stopContext = stopContext
  }
}

/// Opaque cleanup-only authority over the exact XPC session used to submit a
/// start request. It cannot observe status or construct arbitrary requests.
package final class VendorCharonProvisionalStopCapability: @unchecked Sendable {
  private let state: VendorCharonControlState

  init(state: VendorCharonControlState) {
    self.state = state
  }

  deinit {
    state.abandonProvisionalStop()
  }

  package func stop(
    timeoutMilliseconds: Int
  ) async -> VendorCharonControlReceipt {
    await state.stopProvisional(timeoutMilliseconds: timeoutMilliseconds)
  }
}

package final class VendorCharonControlLease: @unchecked Sendable {
  private let state: VendorCharonControlState

  init(state: VendorCharonControlState) {
    self.state = state
  }

  deinit {
    state.abandon()
  }

  package var observation: VendorCharonControlObservation {
    state.observation
  }

  package func stop(
    timeoutMilliseconds: Int
  ) async -> VendorCharonControlReceipt {
    await state.stop(timeoutMilliseconds: timeoutMilliseconds)
  }

  package func waitForConnectedStatus(
    timeoutMilliseconds: Int
  ) async -> VendorCharonStatusWaitResult {
    await state.waitForConnectedStatus(timeoutMilliseconds: timeoutMilliseconds)
  }

  package func setSelectedNCEnabled(
    _ enabled: Bool,
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> VendorCharonControlReceipt {
    await state.setSelectedNCEnabled(
      enabled,
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator
    )
  }

  var statusWaitPending: Bool { state.statusWaitPending }
}
final class VendorCharonNCRouteToggleAttempt: @unchecked Sendable {
  private let lock = NSLock()
  private var cancelled = false
  private var identity: UInt64?

  var isCancelled: Bool { lock.withLock { cancelled } }

  func activate(identity: UInt64) -> Bool {
    lock.withLock {
      precondition(self.identity == nil)
      self.identity = identity
      return !cancelled
    }
  }

  func cancel() -> UInt64? {
    lock.withLock {
      cancelled = true
      return identity
    }
  }
}
