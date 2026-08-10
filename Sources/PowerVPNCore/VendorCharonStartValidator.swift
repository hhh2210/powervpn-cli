import Foundation

public enum VendorCharonStartValidator {
  public static let maximumTextBytes = 1_048_576

  public static func validate(_ candidate: VendorCharonStartCandidate)
    -> VendorCharonStartValidation
  {
    let lineageStatus = VendorCharonStartLineageValidator.status(of: candidate)
    let reports = VendorCharonStartContract.orderedRules.map {
      report(for: $0, candidate: candidate)
    }
    return VendorCharonStartValidation(
      fieldReports: reports,
      lineageStatus: lineageStatus,
      snapshot: lineageStatus != .consistent
        || reports.contains(where: { $0.availability.blocksSnapshot })
        ? nil : VendorCharonStartSnapshot(candidate: candidate)
    )
  }

  private static func report(
    for rule: VendorCharonStartFieldRule,
    candidate: VendorCharonStartCandidate
  ) -> VendorCharonStartFieldReport {
    switch rule.field {
    case .type, .rpc: return make(rule, .generated, [.generatedConstant])
    case .common, .tunnels:
      return make(rule, .generated, [.generatedContainer])
    case .sessionID:
      return text(rule, candidate.common?.sessionID, "common.sessionid", candidate.lineage)
    case .vip: return text(rule, candidate.common?.vip, "common.vip", candidate.lineage)
    case .vipv6: return text(rule, candidate.common?.vipv6, "common.vipv6", candidate.lineage)
    case .gateway:
      return text(rule, candidate.common?.gateway, "common.gateway", candidate.lineage)
    case .ikePort:
      return integer(rule, candidate.common?.ikePort, "common.ike_port", candidate.lineage)
    case .majorVersion:
      return integer(
        rule, candidate.common?.majorVersion, "common.majorVersion", candidate.lineage)
    case .ike: return text(rule, candidate.common?.ike, "common.ike", candidate.lineage)
    case .esp: return text(rule, candidate.common?.esp, "common.esp", candidate.lineage)
    case .psk: return text(rule, candidate.common?.psk, "common.psk", candidate.lineage)
    case .ikeLifetime:
      return integer(
        rule, candidate.common?.ikeLifetime, "common.ike_life_time", candidate.lineage)
    case .ipsecLifetime:
      return integer(
        rule, candidate.common?.ipsecLifetime, "common.ipsec_life_time", candidate.lineage)
    case .authority:
      return tunnelInteger(rule, candidate, \VendorCharonStartTunnelCandidate.authority)
    case .status:
      return tunnelInteger(rule, candidate, \VendorCharonStartTunnelCandidate.status)
    case .tunnelName:
      return tunnelText(rule, candidate, \VendorCharonStartTunnelCandidate.tunnelName)
    case .family:
      return tunnelInteger(rule, candidate, \VendorCharonStartTunnelCandidate.family)
    case .resourceFlag:
      return tunnelInteger(rule, candidate, \VendorCharonStartTunnelCandidate.resourceFlag)
    case .name: return tunnelText(rule, candidate, \VendorCharonStartTunnelCandidate.name)
    case .routes: return tunnelRoutes(rule, candidate)
    case .mapID: return tunnelText(rule, candidate, \VendorCharonStartTunnelCandidate.mapID)
    case .negotiateMode:
      return tunnelInteger(rule, candidate, \VendorCharonStartTunnelCandidate.negotiateMode)
    case .routeNetwork: return routeText(rule, candidate)
    case .routePrefix: return routePrefix(rule, candidate)
    }
  }

  private static func text(
    _ rule: VendorCharonStartFieldRule,
    _ value: VendorCharonStartTextValue?,
    _ path: String,
    _ expectedLineage: VendorCharonStartLineage?
  ) -> VendorCharonStartFieldReport {
    guard let value else { return absent(rule, path) }
    return validLineage(value.lineage, expectedLineage)
      && validText(value.value, allowsEmpty: rule.allowsEmptyText)
      ? make(rule, .available, [value.source])
      : make(rule, .invalid, [value.source], path: path)
  }

  private static func integer(
    _ rule: VendorCharonStartFieldRule,
    _ value: VendorCharonStartIntegerValue?,
    _ path: String,
    _ expectedLineage: VendorCharonStartLineage?
  ) -> VendorCharonStartFieldReport {
    guard let value else { return absent(rule, path) }
    return validLineage(value.lineage, expectedLineage)
      ? make(rule, .available, [value.source])
      : make(rule, .invalid, [value.source], path: path)
  }

  private static func tunnelText(
    _ rule: VendorCharonStartFieldRule,
    _ candidate: VendorCharonStartCandidate,
    _ keyPath: KeyPath<VendorCharonStartTunnelCandidate, VendorCharonStartTextValue?>
  ) -> VendorCharonStartFieldReport {
    guard let tunnels = candidate.tunnels, !tunnels.isEmpty else {
      return rule.requirement.blocksWhenAbsent
        ? make(rule, .missingRequired, path: rule.field.rawValue)
        : make(rule, .absentOptional)
    }
    var sources: [VendorCharonStartMaterialSource] = []
    var sawValue = false
    for (index, tunnel) in tunnels.enumerated() {
      guard let value = tunnel[keyPath: keyPath] else {
        if rule.requirement.blocksWhenAbsent { return absent(rule, path(rule.field, index)) }
        continue
      }
      sawValue = true
      sources.append(value.source)
      if !validLineage(value.lineage, candidate.lineage)
        || !validText(value.value, allowsEmpty: rule.allowsEmptyText)
      {
        return make(rule, .invalid, unique(sources), path: path(rule.field, index))
      }
    }
    return make(rule, sawValue ? .available : .absentOptional, unique(sources))
  }

  private static func tunnelInteger(
    _ rule: VendorCharonStartFieldRule,
    _ candidate: VendorCharonStartCandidate,
    _ keyPath: KeyPath<VendorCharonStartTunnelCandidate, VendorCharonStartIntegerValue?>
  ) -> VendorCharonStartFieldReport {
    guard let tunnels = candidate.tunnels, !tunnels.isEmpty else {
      return rule.requirement.blocksWhenAbsent
        ? make(rule, .missingRequired, path: rule.field.rawValue)
        : make(rule, .absentOptional)
    }
    var sources: [VendorCharonStartMaterialSource] = []
    var sawValue = false
    for (index, tunnel) in tunnels.enumerated() {
      guard let value = tunnel[keyPath: keyPath] else {
        if rule.requirement.blocksWhenAbsent { return absent(rule, path(rule.field, index)) }
        continue
      }
      sawValue = true
      sources.append(value.source)
      if !validLineage(value.lineage, candidate.lineage) {
        return make(rule, .invalid, unique(sources), path: path(rule.field, index))
      }
    }
    return make(rule, sawValue ? .available : .absentOptional, unique(sources))
  }

  private static func tunnelRoutes(
    _ rule: VendorCharonStartFieldRule,
    _ candidate: VendorCharonStartCandidate
  ) -> VendorCharonStartFieldReport {
    guard let tunnels = candidate.tunnels, !tunnels.isEmpty else {
      return make(rule, .missingRequired, path: rule.field.rawValue)
    }
    for (index, tunnel) in tunnels.enumerated() where tunnel.routes == nil {
      return absent(rule, path(rule.field, index))
    }
    return make(rule, .available, [.generatedContainer])
  }

  private static func routeText(
    _ rule: VendorCharonStartFieldRule,
    _ candidate: VendorCharonStartCandidate
  ) -> VendorCharonStartFieldReport {
    let routes = flattenedRoutes(candidate)
    guard !routes.isEmpty else { return make(rule, .notApplicable) }
    var sources: [VendorCharonStartMaterialSource] = []
    for item in routes {
      guard let value = item.route.network else { return absent(rule, item.path + ".net") }
      sources.append(value.source)
      if !validLineage(value.lineage, candidate.lineage)
        || !validText(value.value, allowsEmpty: rule.allowsEmptyText)
      {
        return make(rule, .invalid, unique(sources), path: item.path + ".net")
      }
    }
    return make(rule, .available, unique(sources))
  }

  private static func routePrefix(
    _ rule: VendorCharonStartFieldRule,
    _ candidate: VendorCharonStartCandidate
  ) -> VendorCharonStartFieldReport {
    let routes = flattenedRoutes(candidate)
    guard !routes.isEmpty else { return make(rule, .notApplicable) }
    var sources: [VendorCharonStartMaterialSource] = []
    for item in routes {
      guard let value = item.route.prefix else { return absent(rule, item.path + ".prfix") }
      sources.append(value.source)
      if !validLineage(value.lineage, candidate.lineage) || !validPrefix(value.value) {
        return make(rule, .invalid, unique(sources), path: item.path + ".prfix")
      }
    }
    return make(rule, .available, unique(sources))
  }

  private static func flattenedRoutes(_ candidate: VendorCharonStartCandidate)
    -> [(route: VendorCharonStartRouteCandidate, path: String)]
  {
    (candidate.tunnels ?? []).enumerated().flatMap { tunnelIndex, tunnel in
      (tunnel.routes ?? []).enumerated().map { routeIndex, route in
        (route, "tunnels[\(tunnelIndex)].routes[\(routeIndex)]")
      }
    }
  }

  private static func validText(
    _ material: any VendorCharonStartTextMaterial,
    allowsEmpty: Bool = false
  ) -> Bool {
    let minimum = allowsEmpty ? 0 : 1
    let declaredByteCount = material.byteCount
    guard (minimum...maximumTextBytes).contains(declaredByteCount) else { return false }
    return
      (try? material.withUnsafeUTF8Bytes { bytes in
        bytes.count == declaredByteCount && !bytes.contains(0)
      }) == true
  }

  private static func validLineage(
    _ lineage: VendorCharonStartLineage,
    _ expected: VendorCharonStartLineage?
  ) -> Bool {
    VendorCharonStartLineageValidator.matches(lineage, expected: expected)
  }

  private static func validPrefix(_ prefix: VendorCharonRoutePrefix) -> Bool {
    switch prefix {
    case .integer(let value): return (0...128).contains(value)
    case .decimalText(let material):
      guard validText(material) else { return false }
      return
        (try? material.withUnsafeUTF8Bytes { bytes in
          var value: Int32 = 0
          for byte in bytes {
            guard (0x30...0x39).contains(byte) else { return false }
            let (scaled, overflow1) = value.multipliedReportingOverflow(by: 10)
            let (next, overflow2) = scaled.addingReportingOverflow(Int32(byte - 0x30))
            guard !overflow1, !overflow2 else { return false }
            value = next
          }
          return (0...128).contains(value)
        }) == true
    }
  }

  private static func absent(
    _ rule: VendorCharonStartFieldRule,
    _ path: String
  ) -> VendorCharonStartFieldReport {
    rule.requirement.blocksWhenAbsent
      ? make(rule, .missingRequired, path: path)
      : make(rule, .absentOptional)
  }

  private static func make(
    _ rule: VendorCharonStartFieldRule,
    _ availability: VendorCharonStartFieldAvailability,
    _ sources: [VendorCharonStartMaterialSource] = [],
    path: String? = nil
  ) -> VendorCharonStartFieldReport {
    VendorCharonStartFieldReport(
      field: rule.field,
      requirement: rule.requirement,
      availability: availability,
      sources: sources,
      firstIssuePath: path
    )
  }

  private static func path(_ field: VendorCharonStartField, _ tunnel: Int) -> String {
    field.rawValue.replacingOccurrences(of: "tunnels[]", with: "tunnels[\(tunnel)]")
  }

  private static func unique(_ sources: [VendorCharonStartMaterialSource])
    -> [VendorCharonStartMaterialSource]
  {
    VendorCharonStartMaterialSource.allCases.filter(sources.contains)
  }
}
