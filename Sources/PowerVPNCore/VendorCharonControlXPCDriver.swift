import Dispatch
@preconcurrency import XPC

enum VendorCharonControlConnectionEvent: Equatable, Sendable {
  case status(VendorCharonStatusSignal)
  case emptyDispatcherTail
  case unexpectedDictionary
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedConnectionEvent
}

enum VendorCharonControlReplyEvent: Equatable, Sendable {
  case emptyAcknowledgement
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedPayload
}

protocol VendorCharonControlConnectionDriving: AnyObject, Sendable {
  func submit(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> VendorXPCSessionSubmission

  func cancel()
}

final class SystemVendorCharonControlConnectionDriver: @unchecked Sendable,
  VendorCharonControlConnectionDriving
{
  static let serviceName = "com.leadsec.charon-xpc"

  private let session: VendorXPCSession

  init(
    queue: DispatchQueue,
    connectionEventHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) {
    session = VendorXPCSession(
      queue: queue,
      incomingDecoder: { object in
        connectionEventHandler(VendorCharonControlWireCodec.connectionEvent(object))
      },
      cancellationHandler: { outcome in
        connectionEventHandler(Self.connectionEvent(outcome))
      }
    )
  }

  func submit(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> VendorXPCSessionSubmission {
    session.send(
      request,
      replyDecoder: { object in
        replyHandler(VendorCharonControlWireCodec.replyEvent(object))
      },
      failureHandler: { outcome in
        replyHandler(Self.replyEvent(outcome))
      }
    )
  }

  func cancel() { session.cancel() }

  private static func connectionEvent(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonControlConnectionEvent {
    switch outcome {
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .connectionInvalid: return .connectionInvalid
    default: return .unexpectedXPCError
    }
  }

  private static func replyEvent(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonControlReplyEvent {
    switch outcome {
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .connectionInvalid: return .connectionInvalid
    default: return .unexpectedXPCError
    }
  }
}

enum VendorCharonControlWireCodec {
  static func makeStopRequest() -> xpc_object_t {
    let request = xpc_dictionary_create(nil, nil, 0)
    for field in VendorCharonStopContract.orderedFields {
      field.key.withCString { key in
        field.value.withCString { value in
          xpc_dictionary_set_string(request, key, value)
        }
      }
    }
    precondition(xpc_dictionary_get_count(request) == 2)
    return request
  }

  static func connectionEvent(_ object: xpc_object_t) -> VendorCharonControlConnectionEvent {
    if object === XPC_ERROR_CONNECTION_INTERRUPTED { return .connectionInterrupted }
    if object === XPC_ERROR_CONNECTION_INVALID { return .connectionInvalid }
    if #available(macOS 15.0, *), object === XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT {
      return .peerCodeSigningRequirement
    }
    let type = xpc_get_type(object)
    if type == XPC_TYPE_ERROR { return .unexpectedXPCError }
    guard type == XPC_TYPE_DICTIONARY else { return .unexpectedConnectionEvent }
    if xpc_dictionary_get_count(object) == 0 { return .emptyDispatcherTail }
    guard hasExactStatusShape(object) else { return .unexpectedDictionary }
    return .status(
      VendorCharonStatusSignal(
        type: xpc_dictionary_get_int64(object, "type"),
        phase: xpc_dictionary_get_int64(object, "phase"),
        state: xpc_dictionary_get_int64(object, "state")
      ))
  }

  static func replyEvent(_ object: xpc_object_t) -> VendorCharonControlReplyEvent {
    if object === XPC_ERROR_CONNECTION_INTERRUPTED { return .connectionInterrupted }
    if object === XPC_ERROR_CONNECTION_INVALID { return .connectionInvalid }
    if #available(macOS 15.0, *), object === XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT {
      return .peerCodeSigningRequirement
    }
    let type = xpc_get_type(object)
    if type == XPC_TYPE_ERROR { return .unexpectedXPCError }
    guard type == XPC_TYPE_DICTIONARY, xpc_dictionary_get_count(object) == 0 else {
      return .unexpectedPayload
    }
    return .emptyAcknowledgement
  }

  private static func hasExactStatusShape(_ object: xpc_object_t) -> Bool {
    guard xpc_dictionary_get_count(object) == 4 else { return false }
    return hasType(object, key: "name", type: XPC_TYPE_STRING)
      && hasType(object, key: "type", type: XPC_TYPE_INT64)
      && hasType(object, key: "phase", type: XPC_TYPE_INT64)
      && hasType(object, key: "state", type: XPC_TYPE_INT64)
  }

  private static func hasType(
    _ object: xpc_object_t,
    key: String,
    type: xpc_type_t
  ) -> Bool {
    guard let value = xpc_dictionary_get_value(object, key) else { return false }
    return xpc_get_type(value) == type
  }
}

enum VendorCharonStopContract {
  static let orderedFields = [
    VendorXPCRequestField(key: "type", value: "rpc"),
    VendorXPCRequestField(key: "rpc", value: "stop_connection"),
  ]
}
