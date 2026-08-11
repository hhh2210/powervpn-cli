public enum VendorCharonStartField: String, CaseIterable, Codable, Sendable {
  case type
  case rpc
  case common
  case tunnels
  case sessionID = "common.sessionid"
  case vip = "common.vip"
  case vipv6 = "common.vipv6"
  case gateway = "common.gateway"
  case ikePort = "common.ike_port"
  case majorVersion = "common.majorVersion"
  case ike = "common.ike"
  case esp = "common.esp"
  case psk = "common.psk"
  case ikeLifetime = "common.ike_life_time"
  case ipsecLifetime = "common.ipsec_life_time"
  case authority = "tunnels[].authority"
  case status = "tunnels[].status"
  case tunnelName = "tunnels[].tunnel-name"
  case family = "tunnels[].family"
  case resourceFlag = "tunnels[].rflag"
  case name = "tunnels[].name"
  case routes = "tunnels[].routes"
  case mapID = "tunnels[].mapid"
  case negotiateMode = "tunnels[].negotiate-mode"
  case routeNetwork = "tunnels[].routes[].net"
  case routePrefix = "tunnels[].routes[].prfix"
}

public enum VendorCharonStartFieldRequirement: String, Codable, Sendable {
  case required
  case optional
  case requiredPerTunnel = "required_per_tunnel"
  case optionalPerTunnel = "optional_per_tunnel"
  case requiredPerRoute = "required_per_route"

  public var blocksWhenAbsent: Bool {
    switch self {
    case .required, .requiredPerTunnel, .requiredPerRoute: true
    case .optional, .optionalPerTunnel: false
    }
  }
}

public enum VendorCharonStartValueKind: String, Codable, Sendable {
  case string
  case int32
  case dictionary
  case array
  case routePrefix
}

public struct VendorCharonStartFieldRule: Codable, Equatable, Sendable {
  public let field: VendorCharonStartField
  public let requirement: VendorCharonStartFieldRequirement
  public let valueKind: VendorCharonStartValueKind
  public let allowsEmptyText: Bool

  public init(
    field: VendorCharonStartField,
    requirement: VendorCharonStartFieldRequirement,
    valueKind: VendorCharonStartValueKind,
    allowsEmptyText: Bool = false
  ) {
    self.field = field
    self.requirement = requirement
    self.valueKind = valueKind
    self.allowsEmptyText = allowsEmptyText
  }
}

public enum VendorCharonStartMaterialSource: String, CaseIterable, Codable, Sendable {
  case generatedConstant = "generated_constant"
  case generatedContainer = "generated_container"
  case authenticatedPortalResource = "authenticated_portal_resource"
  case authenticatedPortalOrigin = "authenticated_portal_origin"
  case authenticatedPortalMetadata = "authenticated_portal_metadata"
}

public enum VendorCharonStartContract {
  public static let requestType = "rpc"
  public static let requestRPC = "start_connection"

  public static let orderedRules: [VendorCharonStartFieldRule] = [
    rule(.type, .required, .string),
    rule(.rpc, .required, .string),
    rule(.common, .required, .dictionary),
    rule(.tunnels, .required, .array),
    rule(.sessionID, .required, .string),
    rule(.vip, .optional, .string),
    rule(.vipv6, .optional, .string),
    rule(.gateway, .required, .string),
    rule(.ikePort, .required, .int32),
    rule(.majorVersion, .required, .int32),
    rule(.ike, .required, .string),
    rule(.esp, .required, .string),
    rule(.psk, .required, .string),
    rule(.ikeLifetime, .required, .int32),
    rule(.ipsecLifetime, .required, .int32),
    rule(.authority, .requiredPerTunnel, .int32),
    rule(.status, .requiredPerTunnel, .int32),
    rule(.tunnelName, .requiredPerTunnel, .string),
    rule(.family, .requiredPerTunnel, .int32),
    rule(.resourceFlag, .requiredPerTunnel, .int32),
    rule(.name, .requiredPerTunnel, .string, allowsEmptyText: true),
    rule(.routes, .requiredPerTunnel, .array),
    rule(.mapID, .requiredPerTunnel, .string),
    rule(.negotiateMode, .optionalPerTunnel, .int32),
    rule(.routeNetwork, .requiredPerRoute, .string),
    rule(.routePrefix, .requiredPerRoute, .routePrefix),
  ]

  private static func rule(
    _ field: VendorCharonStartField,
    _ requirement: VendorCharonStartFieldRequirement,
    _ kind: VendorCharonStartValueKind,
    allowsEmptyText: Bool = false
  ) -> VendorCharonStartFieldRule {
    VendorCharonStartFieldRule(
      field: field,
      requirement: requirement,
      valueKind: kind,
      allowsEmptyText: allowsEmptyText
    )
  }
}
