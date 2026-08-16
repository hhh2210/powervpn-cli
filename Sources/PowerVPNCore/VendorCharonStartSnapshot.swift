public protocol VendorCharonStartTextMaterial: Sendable {
  var byteCount: Int { get }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result
}

public struct VendorCharonStartValue<Value: Sendable>: Sendable {
  public let value: Value
  public let source: VendorCharonStartMaterialSource
  package let lineage: VendorCharonStartLineage

  public init(
    value: Value,
    source: VendorCharonStartMaterialSource,
    lineage: VendorCharonStartLineage
  ) {
    self.value = value
    self.source = source
    self.lineage = lineage
  }
}

public typealias VendorCharonStartTextValue =
  VendorCharonStartValue<any VendorCharonStartTextMaterial>
public typealias VendorCharonStartIntegerValue = VendorCharonStartValue<Int32>
public typealias VendorCharonStartPrefixValue = VendorCharonStartValue<VendorCharonRoutePrefix>

public enum VendorCharonRoutePrefix: Sendable {
  case integer(Int32)
  case decimalText(any VendorCharonStartTextMaterial)
}

public struct VendorCharonStartCommonCandidate: Sendable {
  public let sessionID: VendorCharonStartTextValue?
  public let vip: VendorCharonStartTextValue?
  public let vipv6: VendorCharonStartTextValue?
  public let gateway: VendorCharonStartTextValue?
  public let ikePort: VendorCharonStartIntegerValue?
  public let majorVersion: VendorCharonStartIntegerValue?
  public let ike: VendorCharonStartTextValue?
  public let esp: VendorCharonStartTextValue?
  public let psk: VendorCharonStartTextValue?
  public let ikeLifetime: VendorCharonStartIntegerValue?
  public let ipsecLifetime: VendorCharonStartIntegerValue?

  public init(
    sessionID: VendorCharonStartTextValue? = nil,
    vip: VendorCharonStartTextValue? = nil,
    vipv6: VendorCharonStartTextValue? = nil,
    gateway: VendorCharonStartTextValue? = nil,
    ikePort: VendorCharonStartIntegerValue? = nil,
    majorVersion: VendorCharonStartIntegerValue? = nil,
    ike: VendorCharonStartTextValue? = nil,
    esp: VendorCharonStartTextValue? = nil,
    psk: VendorCharonStartTextValue? = nil,
    ikeLifetime: VendorCharonStartIntegerValue? = nil,
    ipsecLifetime: VendorCharonStartIntegerValue? = nil
  ) {
    self.sessionID = sessionID
    self.vip = vip
    self.vipv6 = vipv6
    self.gateway = gateway
    self.ikePort = ikePort
    self.majorVersion = majorVersion
    self.ike = ike
    self.esp = esp
    self.psk = psk
    self.ikeLifetime = ikeLifetime
    self.ipsecLifetime = ipsecLifetime
  }
}

public struct VendorCharonStartRouteCandidate: Sendable {
  public let network: VendorCharonStartTextValue?
  public let prefix: VendorCharonStartPrefixValue?

  public init(
    network: VendorCharonStartTextValue? = nil,
    prefix: VendorCharonStartPrefixValue? = nil
  ) {
    self.network = network
    self.prefix = prefix
  }
}

public struct VendorCharonStartTunnelCandidate: Sendable {
  public let authority: VendorCharonStartIntegerValue?
  public let status: VendorCharonStartIntegerValue?
  public let tunnelName: VendorCharonStartTextValue?
  public let family: VendorCharonStartIntegerValue?
  public let resourceFlag: VendorCharonStartIntegerValue?
  public let name: VendorCharonStartTextValue?
  public let routes: [VendorCharonStartRouteCandidate]?
  public let mapID: VendorCharonStartTextValue?
  public let negotiateMode: VendorCharonStartIntegerValue?

  public init(
    authority: VendorCharonStartIntegerValue? = nil,
    status: VendorCharonStartIntegerValue? = nil,
    tunnelName: VendorCharonStartTextValue? = nil,
    family: VendorCharonStartIntegerValue? = nil,
    resourceFlag: VendorCharonStartIntegerValue? = nil,
    name: VendorCharonStartTextValue? = nil,
    routes: [VendorCharonStartRouteCandidate]? = nil,
    mapID: VendorCharonStartTextValue? = nil,
    negotiateMode: VendorCharonStartIntegerValue? = nil
  ) {
    self.authority = authority
    self.status = status
    self.tunnelName = tunnelName
    self.family = family
    self.resourceFlag = resourceFlag
    self.name = name
    self.routes = routes
    self.mapID = mapID
    self.negotiateMode = negotiateMode
  }
}

public struct VendorCharonStartCandidate: Sendable {
  package let lineage: VendorCharonStartLineage?
  public let common: VendorCharonStartCommonCandidate?
  public let tunnels: [VendorCharonStartTunnelCandidate]?

  public init(
    lineage: VendorCharonStartLineage? = nil,
    common: VendorCharonStartCommonCandidate? = nil,
    tunnels: [VendorCharonStartTunnelCandidate]? = nil
  ) {
    self.lineage = lineage
    self.common = common
    self.tunnels = tunnels
  }
}

public enum VendorCharonStartFieldAvailability: String, Codable, Sendable {
  case generated
  case available
  case absentOptional = "absent_optional"
  case notApplicable = "not_applicable"
  case missingRequired = "missing_required"
  case invalid

  public var blocksSnapshot: Bool {
    self == .missingRequired || self == .invalid
  }
}

public struct VendorCharonStartFieldReport: Codable, Equatable, Sendable {
  public let field: VendorCharonStartField
  public let requirement: VendorCharonStartFieldRequirement
  public let availability: VendorCharonStartFieldAvailability
  public let sources: [VendorCharonStartMaterialSource]
  public let firstIssuePath: String?
}

/// Opaque proof that one nested candidate passed the complete Core contract.
/// The value is deliberately non-Codable and exposes no field material.
public struct VendorCharonStartSnapshot: Sendable {
  let candidate: VendorCharonStartCandidate
  package let selectedTunnelEncodedIndex: Int?

  init(candidate: VendorCharonStartCandidate) {
    self.candidate = candidate
    selectedTunnelEncodedIndex = candidate.tunnels?.count == 1 ? 0 : nil
  }

  private init(candidate: VendorCharonStartCandidate, selectedTunnelEncodedIndex: Int) {
    self.candidate = candidate
    self.selectedTunnelEncodedIndex = selectedTunnelEncodedIndex
  }

  package func selectingTunnel(
    atEncodedIndex index: Int
  ) -> VendorCharonStartSnapshot? {
    guard let tunnels = candidate.tunnels, tunnels.indices.contains(index) else {
      return nil
    }
    return VendorCharonStartSnapshot(
      candidate: candidate,
      selectedTunnelEncodedIndex: index
    )
  }

  public var tunnelCount: Int { candidate.tunnels?.count ?? 0 }
}

public struct VendorCharonStartValidation: Sendable {
  public let fieldReports: [VendorCharonStartFieldReport]
  public let lineageStatus: VendorCharonStartLineageStatus
  public let snapshot: VendorCharonStartSnapshot?

  public var complete: Bool { snapshot != nil }

  public var firstMissingField: VendorCharonStartField? {
    fieldReports.first(where: { $0.availability.blocksSnapshot })?.field
  }

  public var firstMissingPath: String? {
    fieldReports.first(where: { $0.availability.blocksSnapshot })?.firstIssuePath
  }
}
