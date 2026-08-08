import Foundation

public struct TunnelSpec: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let gateway: String
  public let ikeVersion: Int
  public let exchangeMode: ExchangeMode
  public let authentication: Authentication
  public let localIdentifier: String
  public let remoteIdentifier: String
  public let tunnelName: String?
  public let virtualIP: String?
  public let natTraversal: ObservationState
  public let sessionBinding: ExternalReference?
  public let mapID: String?
  public let credentialReference: ExternalReference?
  public let ikeProposal: [String]
  public let espProposal: [String]
  public let modeConfig: ObservationState
  public let vendorIds: [String]
  public let routes: [Route]
  public let resourceOperations: [ResourceOperation]
  public let resources: [Resource]

  public init(
    schemaVersion: Int = 1,
    gateway: String,
    ikeVersion: Int,
    exchangeMode: ExchangeMode,
    authentication: Authentication,
    localIdentifier: String,
    remoteIdentifier: String,
    tunnelName: String? = nil,
    virtualIP: String? = nil,
    natTraversal: ObservationState = .unknown,
    sessionBinding: ExternalReference? = nil,
    mapID: String? = nil,
    credentialReference: ExternalReference? = nil,
    ikeProposal: [String],
    espProposal: [String],
    modeConfig: ObservationState = .unknown,
    vendorIds: [String],
    routes: [Route] = [],
    resourceOperations: [ResourceOperation] = [.unknown],
    resources: [Resource]
  ) {
    self.schemaVersion = schemaVersion
    self.gateway = gateway
    self.ikeVersion = ikeVersion
    self.exchangeMode = exchangeMode
    self.authentication = authentication
    self.localIdentifier = localIdentifier
    self.remoteIdentifier = remoteIdentifier
    self.tunnelName = tunnelName
    self.virtualIP = virtualIP
    self.natTraversal = natTraversal
    self.sessionBinding = sessionBinding
    self.mapID = mapID
    self.credentialReference = credentialReference
    self.ikeProposal = ikeProposal
    self.espProposal = espProposal
    self.modeConfig = modeConfig
    self.vendorIds = vendorIds
    self.routes = routes
    self.resourceOperations = resourceOperations
    self.resources = resources
  }

  public enum ExchangeMode: String, Codable, Sendable {
    case main
    case aggressive
    case unknown
  }

  public struct Authentication: Codable, Equatable, Sendable {
    public let machine: String
    public let extended: String

    public init(machine: String, extended: String) {
      self.machine = machine
      self.extended = extended
    }
  }

  public enum ObservationState: String, Codable, Sendable {
    case observed
    case unsupported
    case unknown
  }

  public struct ExternalReference: Codable, Equatable, Sendable {
    public let storage: ReferenceStorage
    public let identifier: String

    public init(storage: ReferenceStorage, identifier: String) {
      self.storage = storage
      self.identifier = identifier
    }
  }

  public enum ReferenceStorage: String, Codable, Sendable {
    case keychain
    case memory
    case opaque
    case unknown
  }

  public struct Route: Codable, Equatable, Sendable {
    public let identifier: String
    public let destination: String

    public init(identifier: String, destination: String) {
      self.identifier = identifier
      self.destination = destination
    }
  }

  public enum ResourceOperation: String, Codable, Sendable {
    case addRule = "ADDRULE"
    case deleteRule = "DELRULE"
    case unknown
  }

  public struct Resource: Codable, Equatable, Sendable {
    public let name: String
    public let ruleIdentifier: String?
    public let remoteTrafficSelectors: [String]

    public init(
      name: String,
      ruleIdentifier: String? = nil,
      remoteTrafficSelectors: [String]
    ) {
      self.name = name
      self.ruleIdentifier = ruleIdentifier
      self.remoteTrafficSelectors = remoteTrafficSelectors
    }
  }
}
