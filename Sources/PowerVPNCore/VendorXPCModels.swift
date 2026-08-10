@preconcurrency import XPC

public enum VendorXPCGetVersionOutcome: String, Codable, Equatable, Sendable {
  case accepted
  case lockedVersionMismatch = "locked_version_mismatch"
  case getVersionRejected = "get_version_rejected"
  case malformedBusinessEvent = "malformed_business_event"
  case unexpectedReplyPayload = "unexpected_reply_payload"
  case connectionInterrupted = "connection_interrupted"
  case connectionInvalid = "connection_invalid"
  case peerCodeSigningRequirement = "peer_code_signing_requirement"
  case timeout
  case cancelled
  case invalidTimeout = "invalid_timeout"
  case unexpectedXPCError = "unexpected_xpc_error"
  case unexpectedConnectionEvent = "unexpected_connection_event"
}

/// Value-free transport evidence. The peer PID never escapes the synchronous
/// validator used at the business-reply boundary.
public struct VendorXPCGetVersionEvidence: Equatable, Sendable {
  public let outcome: VendorXPCGetVersionOutcome
  public let versionByteLength: Int?
  public let versionMatchesLockedBuild: Bool
  public let getVersionSuccess: Bool
  public let emptyDispatcherTailObserved: Bool
  public let emptyReplyAcknowledgementObserved: Bool
  public let replyPeerGenerationValidated: Bool
  public let connectionCancelRequested: Bool

  public var accepted: Bool {
    outcome == .accepted
      && versionByteLength == 5
      && versionMatchesLockedBuild
      && getVersionSuccess
      && replyPeerGenerationValidated
      && connectionCancelRequested
  }

  public init(
    outcome: VendorXPCGetVersionOutcome,
    versionByteLength: Int? = nil,
    versionMatchesLockedBuild: Bool = false,
    getVersionSuccess: Bool = false,
    emptyDispatcherTailObserved: Bool = false,
    emptyReplyAcknowledgementObserved: Bool = false,
    replyPeerGenerationValidated: Bool = false,
    connectionCancelRequested: Bool
  ) {
    self.outcome = outcome
    self.versionByteLength = versionByteLength
    self.versionMatchesLockedBuild = versionMatchesLockedBuild
    self.getVersionSuccess = getVersionSuccess
    self.emptyDispatcherTailObserved = emptyDispatcherTailObserved
    self.emptyReplyAcknowledgementObserved = emptyReplyAcknowledgementObserved
    self.replyPeerGenerationValidated = replyPeerGenerationValidated
    self.connectionCancelRequested = connectionCancelRequested
  }
}

public protocol VendorXPCTransporting: Sendable {
  func getVersion(
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) async -> Bool
  ) async -> VendorXPCGetVersionEvidence
}

public struct VendorXPCRequestField: Equatable, Sendable {
  public let key: String
  public let value: String

  public init(key: String, value: String) {
    self.key = key
    self.value = value
  }
}

public enum VendorXPCGetVersionRequestContract {
  /// The recovered producer inserts these two fields in this exact order.
  public static let orderedFields = [
    VendorXPCRequestField(key: "type", value: "rpc"),
    VendorXPCRequestField(key: "rpc", value: "get_version"),
  ]
}

enum VendorXPCConnectionEvent: Equatable, Sendable {
  case business(VendorXPCBusinessReply, peerPID: Int32)
  case emptyDispatcherTail
  case malformedBusinessEvent
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedConnectionEvent
}

enum VendorXPCReplyCallbackEvent: Equatable, Sendable {
  case emptyAcknowledgement
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedPayload
}

struct VendorXPCBusinessReply: Equatable, Sendable {
  let versionByteLength: Int
  let versionMatchesLockedBuild: Bool
  let getVersionSuccess: Bool
}

protocol VendorXPCConnectionDriving: AnyObject, Sendable {
  func start(
    connectionEventHandler: @escaping @Sendable (VendorXPCConnectionEvent) -> Void,
    replyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void
  )
  func cancel()
}

enum VendorXPCWireCodec {
  static func makeGetVersionRequest() -> xpc_object_t {
    let request = xpc_dictionary_create(nil, nil, 0)
    for field in VendorXPCGetVersionRequestContract.orderedFields {
      field.key.withCString { key in
        field.value.withCString { value in
          xpc_dictionary_set_string(request, key, value)
        }
      }
    }
    precondition(xpc_dictionary_get_count(request) == 2)
    return request
  }

  static func connectionEvent(
    _ object: xpc_object_t,
    peerPID: Int32
  ) -> VendorXPCConnectionEvent {
    if object === XPC_ERROR_CONNECTION_INTERRUPTED { return .connectionInterrupted }
    if object === XPC_ERROR_CONNECTION_INVALID { return .connectionInvalid }
    if #available(macOS 15.0, *), object === XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT {
      return .peerCodeSigningRequirement
    }
    let type = xpc_get_type(object)
    if type == XPC_TYPE_ERROR { return .unexpectedXPCError }
    guard type == XPC_TYPE_DICTIONARY else { return .unexpectedConnectionEvent }
    if xpc_dictionary_get_count(object) == 0 { return .emptyDispatcherTail }
    guard let reply = businessReply(object) else { return .malformedBusinessEvent }
    return .business(reply, peerPID: peerPID)
  }

  static func sessionConnectionEvent(
    _ object: xpc_object_t
  ) -> VendorCharonEmergencyProbeEvent {
    switch connectionEvent(object, peerPID: 0) {
    case .business(let reply, _): return .business(reply)
    case .emptyDispatcherTail: return .emptyDispatcherTail
    case .malformedBusinessEvent: return .malformedBusinessEvent
    case .connectionInterrupted: return .connectionInterrupted
    case .connectionInvalid: return .connectionInvalid
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .unexpectedXPCError: return .unexpectedXPCError
    case .unexpectedConnectionEvent: return .unexpectedConnectionEvent
    }
  }

  static func replyCallback(_ object: xpc_object_t) -> VendorXPCReplyCallbackEvent {
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

  private static func businessReply(_ object: xpc_object_t) -> VendorXPCBusinessReply? {
    guard xpc_dictionary_get_count(object) == 2,
      let version = xpc_dictionary_get_value(object, "version"),
      xpc_get_type(version) == XPC_TYPE_STRING,
      let success = xpc_dictionary_get_value(object, "get_version"),
      xpc_get_type(success) == XPC_TYPE_BOOL
    else { return nil }

    let length = xpc_string_get_length(version)
    guard length <= Int.max, let bytes = xpc_string_get_string_ptr(version) else {
      return nil
    }
    return VendorXPCBusinessReply(
      versionByteLength: Int(length),
      versionMatchesLockedBuild: matchesLockedVersion(bytes, length: length),
      getVersionSuccess: xpc_bool_get_value(success)
    )
  }

  private static func matchesLockedVersion(
    _ bytes: UnsafePointer<CChar>,
    length: Int
  ) -> Bool {
    guard length == 5 else { return false }
    return UInt8(bitPattern: bytes[0]) == 0x32
      && UInt8(bitPattern: bytes[1]) == 0x34
      && UInt8(bitPattern: bytes[2]) == 0x35
      && UInt8(bitPattern: bytes[3]) == 0x37
      && UInt8(bitPattern: bytes[4]) == 0x32
  }
}
