import Foundation

enum ProtocolCorrelationFieldNamePolicy {
  private static let known: Set<String> = [
    "RESPONSE", "RESULT", "TCPUDP_RESOURCE", "INTERGRATION_INFO", "RESOURCE_LIST",
    "REMOTE_RESOURCE", "NC_RESOURCE", "WEB_RESOURCE", "WEBVPN_RESOURCE",
    "IPSEC_RESOURCE", "VERSION", "SESSION", "USER", "DNS_INFO", "PRIVATE-IP",
    "HOST_LIST", "HOST_ITEM", "code", "hostid", "type", "mac", "verifycode",
    "username", "password", "token", "version", "key", "major", "minor",
    "collect_machineinfo", "login-addr", "login-time", "sid_name",
    "client_jump_pskey", "jump-mapid", "modify_flag", "DOMAIN_HOST", "dnssrv",
    "dns", "dnssrv_v6", "dnsv6", "addr", "vip", "hostItem", "rpc", "common",
    "tunnels", "sessionid", "vipv6", "gateway", "ike_port", "natt_port",
    "majorVersion", "ike", "esp", "psk", "ike_life_time", "ipsec_life_time",
    "authority", "status", "tunnel-name", "family", "rflag", "name", "routes",
    "mapid", "negotiate-mode", "net", "prfix", "route_addr", "updown",
    "kDeleteActionKey", "get", "stop_connection_success", "updown_nc_success",
    "get_tun_name_success", "get_version", "tunnelname", "resources",
    "resources[].name", "common.sessionid", "common.vip", "common.vipv6",
    "common.gateway", "common.ike_port", "common.natt_port", "common.majorVersion",
    "common.ike", "common.esp", "common.psk", "common.ike_life_time",
    "common.ipsec_life_time", "common.hostItem", "tunnels[].authority",
    "tunnels[].status", "tunnels[].tunnel-name", "tunnels[].family", "tunnels[].rflag",
    "tunnels[].name", "tunnels[].routes", "tunnels[].mapid",
    "tunnels[].negotiate-mode", "tunnels[].route_addr", "tunnels[].routes[].net",
    "tunnels[].routes[].prfix",
  ]

  static func allows(_ name: String) -> Bool {
    known.contains(name)
      || name.range(
        of: #"^(?:(?:common|tunnels\[\]|tunnels\[\]\.routes\[\])\.)?unknownField[1-9][0-9]{0,2}$"#,
        options: .regularExpression
      ) != nil
  }
}
