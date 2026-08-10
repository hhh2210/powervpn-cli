import Dispatch
@preconcurrency import XPC

enum VendorCharonControlConnectionEvent: Equatable, Sendable {
  case status
  case emptyDispatcherTail
  case unexpectedDictionary
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedConnectionEvent
}

enum VendorCharonControlReplyEvent: Equatable, Sendable {
  case emptyAcknowledgement(peerPID: Int32)
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
  )

  func cancel()
}

final class SystemVendorCharonControlConnectionDriver: @unchecked Sendable,
  VendorCharonControlConnectionDriving
{
  static let serviceName = "com.leadsec.charon-xpc"

  private let connection: xpc_connection_t
  private let queue: DispatchQueue
  private let connectionEventHandler: @Sendable (VendorCharonControlConnectionEvent) -> Void
  private var activated = false
  private var cancelled = false

  init(
    queue: DispatchQueue,
    connectionEventHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) {
    self.queue = queue
    self.connectionEventHandler = connectionEventHandler
    connection = Self.serviceName.withCString { service in
      xpc_connection_create_mach_service(
        service,
        queue,
        UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED)
      )
    }
  }

  func submit(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) {
    guard !cancelled else {
      replyHandler(.connectionInvalid)
      return
    }
    if !activated {
      xpc_connection_set_event_handler(connection) { [connectionEventHandler] object in
        connectionEventHandler(VendorCharonControlWireCodec.connectionEvent(object))
      }
      xpc_connection_activate(connection)
      activated = true
    }
    xpc_connection_send_message_with_reply(connection, request, queue) { [connection] object in
      replyHandler(
        VendorCharonControlWireCodec.replyEvent(
          object,
          peerPID: xpc_connection_get_pid(connection)
        ))
    }
  }

  func cancel() {
    guard !cancelled else { return }
    cancelled = true
    xpc_connection_set_event_handler(connection) { _ in }
    xpc_connection_cancel(connection)
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
    return hasExactStatusShape(object) ? .status : .unexpectedDictionary
  }

  static func replyEvent(
    _ object: xpc_object_t,
    peerPID: Int32
  ) -> VendorCharonControlReplyEvent {
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
    return .emptyAcknowledgement(peerPID: peerPID)
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
