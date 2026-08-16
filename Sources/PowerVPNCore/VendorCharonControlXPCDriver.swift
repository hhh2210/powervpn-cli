import Darwin
import Dispatch
@preconcurrency import XPC

enum VendorCharonControlConnectionEvent: Equatable, Sendable {
  indirect case decodedDictionary(
    signature: [String],
    event: VendorCharonControlConnectionEvent
  )
  case status(VendorCharonStatusSignal)
  case tunnelNameReported(success: Bool)
  case emptyDispatcherTail
  case unexpectedDictionary
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedConnectionEvent
}

enum VendorCharonControlReplyEvent: Equatable, Sendable {
  indirect case decodedDictionary(
    signature: [String],
    event: VendorCharonControlReplyEvent
  )
  case emptyAcknowledgement
  case ncRouteToggleAcknowledgement(success: Bool)
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
        let signature = VendorCharonControlWireCodec.dictionarySignature(object)
        let event = VendorCharonControlWireCodec.connectionEvent(object)
        connectionEventHandler(
          signature.map {
            .decodedDictionary(signature: $0, event: event)
          } ?? event
        )
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
        let signature = VendorCharonControlWireCodec.dictionarySignature(object)
        let event = VendorCharonControlWireCodec.replyEvent(object)
        replyHandler(
          signature.map {
            .decodedDictionary(signature: $0, event: event)
          } ?? event
        )
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
  static func stopContext(
    copyingGatewayFromStartRequest request: xpc_object_t
  ) -> VendorCharonStopContext? {
    guard xpc_get_type(request) == XPC_TYPE_DICTIONARY,
      let common = xpc_dictionary_get_value(request, "common"),
      xpc_get_type(common) == XPC_TYPE_DICTIONARY,
      let gateway = xpc_dictionary_get_string(common, "gateway")
    else { return nil }
    let copiedGateway = Array(
      UnsafeBufferPointer(start: gateway, count: strlen(gateway) + 1)
    )
    return VendorCharonStopContext(gatewayCString: copiedGateway)
  }

  static func ncRouteToggleContext(
    copyingTunnelNameFromStartRequest request: xpc_object_t,
    selectedTunnelIndex: Int
  ) -> VendorCharonNCRouteToggleContext? {
    guard xpc_get_type(request) == XPC_TYPE_DICTIONARY,
      let tunnels = xpc_dictionary_get_value(request, "tunnels"),
      xpc_get_type(tunnels) == XPC_TYPE_ARRAY,
      selectedTunnelIndex >= 0,
      selectedTunnelIndex < xpc_array_get_count(tunnels)
    else { return nil }
    let tunnel = xpc_array_get_value(tunnels, selectedTunnelIndex)
    guard xpc_get_type(tunnel) == XPC_TYPE_DICTIONARY,
      let tunnelName = xpc_dictionary_get_string(tunnel, "tunnel-name")
    else { return nil }
    return VendorCharonNCRouteToggleContext(
      tunnelNameCString: Array(
        UnsafeBufferPointer(start: tunnelName, count: strlen(tunnelName) + 1)
      )
    )
  }

  static func makeNCRouteToggleRequest(
    context: VendorCharonNCRouteToggleContext,
    enabled: Bool
  ) -> xpc_object_t {
    let request = xpc_dictionary_create(nil, nil, 0)
    for field in VendorCharonNCRouteToggleContract.orderedFields {
      field.key.withCString { key in
        field.value.withCString { value in
          xpc_dictionary_set_string(request, key, value)
        }
      }
    }
    xpc_dictionary_set_bool(request, "updown", enabled)
    context.withTunnelNameCString {
      xpc_dictionary_set_string(request, "tunnel-name", $0)
    }
    precondition(xpc_dictionary_get_count(request) == 4)
    return request
  }

  static func makeStopRequest(
    context: VendorCharonStopContext
  ) -> xpc_object_t {
    let request = xpc_dictionary_create(nil, nil, 0)
    for field in VendorCharonStopContract.orderedFields {
      field.key.withCString { key in
        field.value.withCString { value in
          xpc_dictionary_set_string(request, key, value)
        }
      }
    }
    let common = xpc_dictionary_create(nil, nil, 0)
    context.withGatewayCString { gateway in
      xpc_dictionary_set_string(common, "gateway", gateway)
    }
    xpc_dictionary_set_value(request, "common", common)
    precondition(xpc_dictionary_get_count(request) == 3)
    precondition(xpc_dictionary_get_count(common) == 1)
    return request
  }

  /// Returns sorted top-level key/type tokens only; no XPC value is read.
  static func dictionarySignature(_ object: xpc_object_t) -> [String]? {
    guard xpc_get_type(object) == XPC_TYPE_DICTIONARY else { return nil }
    var fields: [(key: String, type: String)] = []
    xpc_dictionary_apply(object) { key, value in
      fields.append(
        (
          key: String(cString: key),
          type: String(cString: xpc_type_get_name(xpc_get_type(value)))
        ))
      return true
    }
    return fields.sorted { $0.key < $1.key }.map { "\($0.key):\($0.type)" }
  }

  static func signatureDescription(_ signature: [String]) -> String {
    signature.isEmpty ? "{}" : signature.joined(separator: ",")
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
    if let success = tunnelNameReport(object) {
      return .tunnelNameReported(success: success)
    }
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
    guard type == XPC_TYPE_DICTIONARY else { return .unexpectedPayload }
    if xpc_dictionary_get_count(object) == 0 {
      return .emptyAcknowledgement
    }
    guard xpc_dictionary_get_count(object) == 1,
      hasType(object, key: "updown_nc_success", type: XPC_TYPE_BOOL)
    else { return .unexpectedPayload }
    return .ncRouteToggleAcknowledgement(
      success: xpc_dictionary_get_bool(object, "updown_nc_success")
    )
  }

  private static func tunnelNameReport(_ object: xpc_object_t) -> Bool? {
    // Helper setter 0x1001a9924-0x1001a9930 and GUI reader 0x1001cc26d
    // both use this exact key.
    guard hasType(object, key: "get_tun_name_success", type: XPC_TYPE_BOOL) else {
      return nil
    }
    var exactCount = 1
    for key in ["namev4", "namev6"] {
      guard let value = xpc_dictionary_get_value(object, key) else { continue }
      guard xpc_get_type(value) == XPC_TYPE_STRING else { return nil }
      exactCount += 1
    }
    guard xpc_dictionary_get_count(object) == exactCount else { return nil }
    return xpc_dictionary_get_bool(object, "get_tun_name_success")
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

enum VendorCharonNCRouteToggleContract {
  static let orderedFields = [
    VendorXPCRequestField(key: "type", value: "rpc"),
    VendorXPCRequestField(key: "rpc", value: "updown_nc"),
  ]
}

enum VendorCharonStopContract {
  static let orderedFields = [
    VendorXPCRequestField(key: "type", value: "rpc"),
    VendorXPCRequestField(key: "rpc", value: "stop_connection"),
  ]
}
