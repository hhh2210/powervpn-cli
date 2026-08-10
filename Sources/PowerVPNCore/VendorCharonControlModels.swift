package enum VendorCharonControlOperation: String, Equatable, Sendable {
  case startConnection = "start_connection"
  case stopConnection = "stop_connection"
}

package enum VendorCharonControlOutcome: String, Equatable, Sendable {
  case transportAcknowledged = "transport_acknowledged"
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

  package var transportAcknowledged: Bool {
    outcome == .transportAcknowledged
      && requestSent && emptyReplyObserved && peerGenerationValidated
  }

  package var helperMayHaveMutated: Bool { requestSent }

  /// The installed charon helper has no synchronous start/stop business reply.
  package var helperSuccessEstablished: Bool { false }
}

package struct VendorCharonControlObservation: Equatable, Sendable {
  package let statusEventCount: Int
  package let dispatcherTailEventCount: Int
  package let unexpectedDictionaryEventCount: Int
  package let terminalConnectionOutcome: VendorCharonControlOutcome?
}

package struct VendorCharonStartControlResult: Sendable {
  package let receipt: VendorCharonControlReceipt
  package let lease: VendorCharonControlLease?
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
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) -> Bool
  ) async -> VendorCharonControlReceipt {
    await state.stop(
      timeoutMilliseconds: timeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator
    )
  }
}
