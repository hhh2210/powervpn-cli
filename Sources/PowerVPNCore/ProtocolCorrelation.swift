import Foundation

public struct ProtocolCorrelationDocument: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let fixtureClass: FixtureClass
  public let redactionMode: RedactionMode
  public let source: Source
  public let containsSecrets: Bool
  public let containsReplayableCapture: Bool
  public let events: [Event]

  public init(
    schemaVersion: Int = 1,
    fixtureClass: FixtureClass = .valueFreeProtocolCorrelation,
    redactionMode: RedactionMode = .metadataOnlyAtCollection,
    source: Source,
    containsSecrets: Bool = false,
    containsReplayableCapture: Bool = false,
    events: [Event]
  ) {
    self.schemaVersion = schemaVersion
    self.fixtureClass = fixtureClass
    self.redactionMode = redactionMode
    self.source = source
    self.containsSecrets = containsSecrets
    self.containsReplayableCapture = containsReplayableCapture
    self.events = events
  }

  public struct Event: Codable, Equatable, Sendable {
    public let sequence: Int
    public let relativeMilliseconds: Int?
    public let boundary: Boundary
    public let transport: Transport
    public let direction: Direction
    public let kind: MessageKind
    public let operation: Operation
    public let helperFamily: HelperFamily?
    public let method: HTTPMethod?
    public let pathTemplate: String?
    public let statusCode: Int?
    public let resultClass: ResultClass?
    public let evidenceClass: EvidenceClass
    public let confidence: Confidence
    public let fields: [Field]
    public let transitions: [StateTransition]

    public init(
      sequence: Int,
      relativeMilliseconds: Int? = nil,
      boundary: Boundary,
      transport: Transport,
      direction: Direction,
      kind: MessageKind,
      operation: Operation,
      helperFamily: HelperFamily? = nil,
      method: HTTPMethod? = nil,
      pathTemplate: String? = nil,
      statusCode: Int? = nil,
      resultClass: ResultClass? = nil,
      evidenceClass: EvidenceClass,
      confidence: Confidence,
      fields: [Field] = [],
      transitions: [StateTransition] = []
    ) {
      self.sequence = sequence
      self.relativeMilliseconds = relativeMilliseconds
      self.boundary = boundary
      self.transport = transport
      self.direction = direction
      self.kind = kind
      self.operation = operation
      self.helperFamily = helperFamily
      self.method = method
      self.pathTemplate = pathTemplate
      self.statusCode = statusCode
      self.resultClass = resultClass
      self.evidenceClass = evidenceClass
      self.confidence = confidence
      self.fields = fields
      self.transitions = transitions
    }
  }

  public struct Field: Codable, Equatable, Sendable {
    public let name: String
    public let type: FieldType
    public let length: Int?
    public let lengthUnit: LengthUnit?
    public let order: Int
    public let evidenceClass: EvidenceClass
    public let confidence: Confidence

    public init(
      name: String,
      type: FieldType,
      length: Int? = nil,
      lengthUnit: LengthUnit? = nil,
      order: Int,
      evidenceClass: EvidenceClass,
      confidence: Confidence
    ) {
      self.name = name
      self.type = type
      self.length = length
      self.lengthUnit = lengthUnit
      self.order = order
      self.evidenceClass = evidenceClass
      self.confidence = confidence
    }
  }

  public struct StateTransition: Codable, Equatable, Sendable {
    public let domain: StateDomain
    public let from: State
    public let to: State
    public let trigger: Trigger
    public let evidenceClass: EvidenceClass
    public let confidence: Confidence

    public init(
      domain: StateDomain,
      from: State,
      to: State,
      trigger: Trigger,
      evidenceClass: EvidenceClass,
      confidence: Confidence
    ) {
      self.domain = domain
      self.from = from
      self.to = to
      self.trigger = trigger
      self.evidenceClass = evidenceClass
      self.confidence = confidence
    }
  }

  public enum FixtureClass: String, Codable, Sendable {
    case valueFreeProtocolCorrelation = "value_free_protocol_correlation"
  }

  public enum RedactionMode: String, Codable, Sendable {
    case metadataOnlyAtCollection = "metadata_only_at_collection"
  }

  public enum Source: String, Codable, Sendable {
    case synthetic
    case staticBinary = "static_binary"
    case runtimeMetadata = "runtime_metadata"
    case differentialObservation = "differential_observation"
  }

  public enum Boundary: String, Codable, Sendable {
    case controlPlane = "control_plane"
    case xpc
  }

  public enum Transport: String, Codable, Sendable {
    case https
    case webSocket = "websocket"
    case xpc
  }

  public enum Direction: String, Codable, Sendable {
    case clientToServer = "client_to_server"
    case serverToClient = "server_to_client"
    case guiToHelper = "gui_to_helper"
    case helperToGUI = "helper_to_gui"
    case helperEvent = "helper_event"
  }

  public enum MessageKind: String, Codable, Sendable {
    case request
    case response
    case open
    case message
    case keepalive
    case resume
    case close
    case call
    case reply
    case disconnect
  }

  public enum Operation: String, Codable, Sendable {
    case unknown
    case login
    case logout
    case sessionCheck = "session_check"
    case resourceList = "resource_list"
    case resourceActivate = "resource_activate"
    case resourceDeactivate = "resource_deactivate"
    case webSocketOpen = "websocket_open"
    case webSocketMessage = "websocket_message"
    case webSocketKeepalive = "websocket_keepalive"
    case webSocketResume = "websocket_resume"
    case webSocketClose = "websocket_close"
    case startConnection = "start_connection"
    case stopConnection = "stop_connection"
    case restartConnection = "restart_connection"
    case startAllConnections = "start_all_connections"
    case resourceToggleNC = "resource_toggle_nc"
    case resourceToggleIPSec = "resource_toggle_ipsec"
    case queryTunnelName = "query_tunnel_name"
    case getVersion = "get_version"
    case disconnectNotification = "disconnect_notification"
  }

  public enum HelperFamily: String, Codable, Sendable {
    case charon
    case ipsec
  }

  public enum HTTPMethod: String, Codable, Sendable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case patch = "PATCH"
    case delete = "DELETE"
    case head = "HEAD"
  }

  public enum FieldType: String, Codable, Sendable {
    case string
    case number
    case boolean
    case array
    case dictionary
    case data
    case null
    case unknown
  }

  public enum LengthUnit: String, Codable, Sendable {
    case bytes
    case elements
    case fields
  }

  public enum ResultClass: String, Codable, Sendable {
    case success
    case failure
    case disconnect
    case unknown
  }

  public enum EvidenceClass: String, Codable, Sendable {
    case staticBinary = "static_binary"
    case runtimeMetadata = "runtime_metadata"
    case differentialObservation = "differential_observation"
    case synthetic
  }

  public enum Confidence: String, Codable, Sendable {
    case confirmed
    case inferred
    case unknown
  }

  public enum StateDomain: String, Codable, Sendable {
    case authSession = "auth_session"
    case controlChannel = "control_channel"
    case resourceCatalog = "resource_catalog"
    case helperTunnel = "helper_tunnel"
  }

  public enum State: String, Codable, Sendable {
    case unknown
    case signedOut = "signed_out"
    case authenticating
    case valid
    case ready
    case reconnecting
    case expired
    case failed
    case disconnected
    case online
    case resuming
    case backoff
    case unavailable
    case refreshing
    case activationPending = "activation_pending"
    case active
    case deactivationPending = "deactivation_pending"
    case inactive
    case idle
    case connecting
    case established
    case degraded
    case stopped
  }

  public enum Trigger: String, Codable, Sendable {
    case unknown
    case requestSent = "request_sent"
    case responseSuccess = "response_success"
    case responseFailure = "response_failure"
    case socketOpened = "socket_opened"
    case socketClosed = "socket_closed"
    case resumeRequested = "resume_requested"
    case catalogReceived = "catalog_received"
    case activationRequested = "activation_requested"
    case deactivationRequested = "deactivation_requested"
    case helperCall = "helper_call"
    case helperReply = "helper_reply"
    case helperDisconnect = "helper_disconnect"
  }
}
