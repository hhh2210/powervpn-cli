import CPowerVPNXPCSession
import Dispatch
@preconcurrency import XPC

enum VendorXPCSessionSubmission: Equatable, Sendable {
  case submitted
  case rejected(VendorCharonControlOutcome)
}

package enum VendorXPCSessionPreflightStatus: Equatable, Sendable {
  case accepted
  case unsupportedOS
  case rejected
}

package enum VendorXPCSessionContract {
  static var serviceName: String {
    String(cString: power_vpn_xpc_session_service_name())
  }

  static var peerRequirement: String {
    String(cString: power_vpn_xpc_session_peer_requirement())
  }

  package static func runtimePreflight() -> VendorXPCSessionPreflightStatus {
    switch power_vpn_xpc_session_runtime_preflight() {
    case PowerVPNXPCSessionStatusOK: return .accepted
    case PowerVPNXPCSessionStatusUnsupportedOS: return .unsupportedOS
    default: return .rejected
    }
  }

  static var replyFailureOutcome: VendorCharonControlOutcome {
    VendorXPCSession.outcome(PowerVPNXPCSessionStatusReplyFailed)
  }
}

/// Swift owner for one fixed-service, non-reconnecting XPC session.
/// Raw XPC objects are decoded synchronously inside their callback lifetime.
final class VendorXPCSession: @unchecked Sendable {
  typealias IncomingDecoder = @Sendable (xpc_object_t) -> Void
  typealias CancellationHandler = @Sendable (VendorCharonControlOutcome) -> Void

  private var session: OpaquePointer?
  private let creationOutcome: VendorCharonControlOutcome

  init(
    queue: DispatchQueue,
    incomingDecoder: @escaping IncomingDecoder,
    cancellationHandler: @escaping CancellationHandler
  ) {
    var status = PowerVPNXPCSessionStatusOK
    session = power_vpn_xpc_session_create(
      queue,
      { object in
        guard let object else {
          cancellationHandler(.unexpectedXPCError)
          return
        }
        incomingDecoder(object)
      },
      { status in cancellationHandler(Self.outcome(status)) },
      &status
    )
    creationOutcome = Self.outcome(status)
  }

  deinit { cancel() }

  func send(
    _ request: xpc_object_t,
    replyDecoder: @escaping IncomingDecoder,
    failureHandler: @escaping CancellationHandler
  ) -> VendorXPCSessionSubmission {
    guard let session else { return .rejected(creationOutcome) }
    let submitted = power_vpn_xpc_session_send(
      session,
      request
    ) { status, reply in
      guard status == PowerVPNXPCSessionStatusOK, let reply else {
        failureHandler(Self.outcome(status))
        return
      }
      replyDecoder(reply)
    }
    return submitted ? .submitted : .rejected(.connectionInvalid)
  }

  func cancel() {
    guard let session else { return }
    self.session = nil
    power_vpn_xpc_session_cancel(session)
    power_vpn_xpc_session_release(session)
  }

  static func outcome(
    _ status: PowerVPNXPCSessionStatus
  ) -> VendorCharonControlOutcome {
    switch status {
    case PowerVPNXPCSessionStatusOK:
      return .transportAcknowledged
    case PowerVPNXPCSessionStatusRequirementFailed:
      return .peerCodeSigningRequirement
    case PowerVPNXPCSessionStatusCancelled,
      PowerVPNXPCSessionStatusReplyFailed,
      PowerVPNXPCSessionStatusUnsupportedOS,
      PowerVPNXPCSessionStatusCreateFailed,
      PowerVPNXPCSessionStatusActivationFailed:
      return .connectionInvalid
    default:
      return .unexpectedXPCError
    }
  }
}
