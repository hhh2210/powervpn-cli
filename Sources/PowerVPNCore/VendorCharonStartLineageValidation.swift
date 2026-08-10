enum VendorCharonStartLineageValidator {
  static func status(
    of candidate: VendorCharonStartCandidate
  ) -> VendorCharonStartLineageStatus {
    guard let expected = candidate.lineage else { return .missing }
    return allValueLineages(in: candidate).allSatisfy { $0 === expected }
      ? .consistent : .mixed
  }

  static func matches(
    _ lineage: VendorCharonStartLineage,
    expected: VendorCharonStartLineage?
  ) -> Bool {
    guard let expected else { return false }
    return lineage === expected
  }

  private static func allValueLineages(
    in candidate: VendorCharonStartCandidate
  ) -> [VendorCharonStartLineage] {
    var result: [VendorCharonStartLineage] = []
    if let common = candidate.common {
      append(common.sessionID, to: &result)
      append(common.vip, to: &result)
      append(common.vipv6, to: &result)
      append(common.gateway, to: &result)
      append(common.ikePort, to: &result)
      append(common.majorVersion, to: &result)
      append(common.ike, to: &result)
      append(common.esp, to: &result)
      append(common.psk, to: &result)
      append(common.ikeLifetime, to: &result)
      append(common.ipsecLifetime, to: &result)
    }
    for tunnel in candidate.tunnels ?? [] {
      append(tunnel.authority, to: &result)
      append(tunnel.status, to: &result)
      append(tunnel.tunnelName, to: &result)
      append(tunnel.family, to: &result)
      append(tunnel.resourceFlag, to: &result)
      append(tunnel.name, to: &result)
      append(tunnel.mapID, to: &result)
      append(tunnel.negotiateMode, to: &result)
      for route in tunnel.routes ?? [] {
        append(route.network, to: &result)
        append(route.prefix, to: &result)
      }
    }
    return result
  }

  private static func append<Value: Sendable>(
    _ value: VendorCharonStartValue<Value>?,
    to lineages: inout [VendorCharonStartLineage]
  ) {
    if let value { lineages.append(value.lineage) }
  }
}
