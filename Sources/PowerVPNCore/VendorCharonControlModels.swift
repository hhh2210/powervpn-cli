package enum VendorCharonControlOperation: String, Equatable, Sendable {
  case startConnection = "start_connection"
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
  case unexpectedReplyPayload = "unexpected_reply_payload"
  case leaseClosed = "lease_closed"
}

/// Value-free evidence for one bounded helper-control request.
///
/// `requestSent` means the request was handed to libxpc. Even an exact empty
/// reply proves only that the vendor dispatcher handled the request; tunnel
/// success must be established by later network/status evidence.
package struct VendorCharonControlReceipt: Equatable, Sendable {
  package let operation: VendorCharonControlOperation
  package let outcome: VendorCharonControlOutcome
  package let requestSent: Bool
  package let emptyReplyObserved: Bool
  package let peerGenerationValidated: Bool
  package let connectionRetained: Bool
  package let connectionCancelRequested: Bool
  package let encodingError: VendorCharonStartEncodingError?
  package let statusEventCount: Int
  package let dispatcherTailEventCount: Int
  package var statusAtSubmission: VendorCharonStatusClassification? = nil

  package var transportAcknowledged: Bool {
    outcome == .transportAcknowledged
      && requestSent && emptyReplyObserved && peerGenerationValidated
  }

  package var helperMayHaveMutated: Bool { requestSent }

  /// The installed charon helper has no synchronous start/stop business reply.
  package var helperSuccessEstablished: Bool { false }

  /// Transport acknowledgement alone cannot prove route/tunnel cleanup.
  package var cleanupEstablished: Bool { false }
}

package struct VendorCharonControlObservation: Equatable, Sendable {
  package let statusEventCount: Int
  package let latestStatus: VendorCharonStatusSignal?
  package let dispatcherTailEventCount: Int
  package let unexpectedDictionaryEventCount: Int
  package let terminalConnectionOutcome: VendorCharonControlOutcome?
}

package struct VendorCharonStartControlResult: Sendable {
  package let receipt: VendorCharonControlReceipt
  package let lease: VendorCharonControlLease?
  package let provisionalStopCapability: VendorCharonProvisionalStopCapability?

  package init(
    receipt: VendorCharonControlReceipt,
    lease: VendorCharonControlLease?,
    provisionalStopCapability: VendorCharonProvisionalStopCapability? = nil
  ) {
    self.receipt = receipt
    self.lease = lease
    self.provisionalStopCapability = provisionalStopCapability
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

  var statusWaitPending: Bool { state.statusWaitPending }
}
