package enum VendorAppSessionRequiredField:
  String, CaseIterable, Encodable, Equatable, Sendable
{
  case rootType = "root_type"
  case rootRPC = "root_rpc"
  case rootCommon = "root_common"
  case rootTunnels = "root_tunnels"
  case commonAuthport = "common_authport"
  case commonDNS = "common_dns"
  case commonDNSv6 = "common_dnsv6"
  case commonESP = "common_esp"
  case commonGateway = "common_gateway"
  case commonIKE = "common_ike"
  case commonIKELifetime = "common_ike_life_time"
  case commonIKEPort = "common_ike_port"
  case commonIPSecLifetime = "common_ipsec_life_time"
  case commonMajorVersion = "common_major_version"
  case commonName = "common_name"
  case commonNATTPort = "common_natt_port"
  case commonPSK = "common_psk"
  case commonSessionID = "common_sessionid"
  case commonStatus = "common_status"
  case commonSubnet = "common_subnet"
  case commonTunnelNameV4 = "common_tunnelname_v4"
  case commonVIP = "common_vip"
  case commonVIPv6 = "common_vipv6"
  case tunnelRecord = "tunnel_record"
  case tunnelAuthority = "tunnel_authority"
  case tunnelCommand = "tunnel_cmd"
  case tunnelDisplay = "tunnel_display"
  case tunnelEncryption = "tunnel_enc"
  case tunnelExcludes = "tunnel_excludes"
  case tunnelFamily = "tunnel_family"
  case tunnelIcon = "tunnel_icon"
  case tunnelMapID = "tunnel_mapid"
  case tunnelName = "tunnel_name"
  case tunnelNegotiateMode = "tunnel_negotiate_mode"
  case tunnelNotice = "tunnel_notice"
  case tunnelResourceFlag = "tunnel_rflag"
  case tunnelRoutes = "tunnel_routes"
  case tunnelStatus = "tunnel_status"
  case tunnelTunnelName = "tunnel_tunnel_name"
  case routeRecord = "route_record"
  case routeFamily = "route_family"
  case routeMask = "route_mask"
  case routeNetwork = "route_net"
  case routePrefix = "route_prfix"
}

struct VendorAppSessionSnapshotField {
  let key: String
  let diagnostic: VendorAppSessionRequiredField
}

extension VendorAppSessionSnapshotSchema {
  typealias Field = VendorAppSessionSnapshotField

  static let rootFields = [
    Field(key: "type", diagnostic: .rootType),
    Field(key: "rpc", diagnostic: .rootRPC),
    Field(key: "common", diagnostic: .rootCommon),
    Field(key: "tunnels", diagnostic: .rootTunnels),
  ]
  static let commonFields = [
    Field(key: "authport", diagnostic: .commonAuthport),
    Field(key: "dns", diagnostic: .commonDNS),
    Field(key: "dnsv6", diagnostic: .commonDNSv6),
    Field(key: "esp", diagnostic: .commonESP),
    Field(key: "gateway", diagnostic: .commonGateway),
    Field(key: "ike", diagnostic: .commonIKE),
    Field(key: "ike_life_time", diagnostic: .commonIKELifetime),
    Field(key: "ike_port", diagnostic: .commonIKEPort),
    Field(key: "ipsec_life_time", diagnostic: .commonIPSecLifetime),
    Field(key: "majorVersion", diagnostic: .commonMajorVersion),
    Field(key: "name", diagnostic: .commonName),
    Field(key: "natt_port", diagnostic: .commonNATTPort),
    Field(key: "psk", diagnostic: .commonPSK),
    Field(key: "sessionid", diagnostic: .commonSessionID),
    Field(key: "status", diagnostic: .commonStatus),
    Field(key: "subnet", diagnostic: .commonSubnet),
    Field(key: "tunnelnameV4", diagnostic: .commonTunnelNameV4),
    Field(key: "vip", diagnostic: .commonVIP),
    Field(key: "vipv6", diagnostic: .commonVIPv6),
  ]
  static let tunnelFields = [
    Field(key: "authority", diagnostic: .tunnelAuthority),
    Field(key: "cmd", diagnostic: .tunnelCommand),
    Field(key: "display", diagnostic: .tunnelDisplay),
    Field(key: "enc", diagnostic: .tunnelEncryption),
    Field(key: "excludes", diagnostic: .tunnelExcludes),
    Field(key: "family", diagnostic: .tunnelFamily),
    Field(key: "icon", diagnostic: .tunnelIcon),
    Field(key: "mapid", diagnostic: .tunnelMapID),
    Field(key: "name", diagnostic: .tunnelName),
    Field(key: "negotiate-mode", diagnostic: .tunnelNegotiateMode),
    Field(key: "notice", diagnostic: .tunnelNotice),
    Field(key: "rflag", diagnostic: .tunnelResourceFlag),
    Field(key: "routes", diagnostic: .tunnelRoutes),
    Field(key: "status", diagnostic: .tunnelStatus),
    Field(key: "tunnel-name", diagnostic: .tunnelTunnelName),
  ]
  static let routeFields = [
    Field(key: "family", diagnostic: .routeFamily),
    Field(key: "mask", diagnostic: .routeMask),
    Field(key: "net", diagnostic: .routeNetwork),
    Field(key: "prfix", diagnostic: .routePrefix),
  ]

  static let rootKeys = Set(rootFields.map(\.key))
  static let commonKeys = Set(commonFields.map(\.key))
  static let tunnelKeys = Set(tunnelFields.map(\.key))
  static let routeKeys = Set(routeFields.map(\.key))
}
