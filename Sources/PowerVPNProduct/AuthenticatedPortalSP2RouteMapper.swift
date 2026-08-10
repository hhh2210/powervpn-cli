import PowerVPNCore
import PowerVPNPortal

struct PortalSP2RouteMapping {
  let resourceFlag: VendorCharonStartIntegerValue
  let name: VendorCharonStartTextValue?
  let routes: [VendorCharonStartRouteCandidate]?
}

enum AuthenticatedPortalSP2RouteMapper {
  static func map(
    extensions: AuthenticatedPortalResourceElement?,
    lineage: VendorCharonStartLineage
  ) throws -> PortalSP2RouteMapping {
    guard let extensions else { return empty(lineage: lineage) }
    let securedRoutes = try PortalSP2Tree.child(named: "SECURED-ROUTES", of: extensions)
    let securedRange = try PortalSP2Tree.child(named: "SECURED-RANGE", of: extensions)
    let securedRoute = try PortalSP2Tree.child(named: "SECURED-ROUTE", of: extensions)

    var resourceFlag = PortalSP2Value.generatedInteger(0, lineage: lineage)
    var name: VendorCharonStartTextValue? =
      try securedRoutes.flatMap {
        try PortalSP2Value.text(
          try PortalSP2Tree.attribute(named: "name", of: $0),
          lineage: lineage
        )
      } ?? PortalSP2Value.generatedText([], lineage: lineage)
    var sourceElements: [AuthenticatedPortalResourceElement] = []

    if let securedRoutes {
      let ranges = try PortalSP2Tree.children(named: "RANGE", of: securedRoutes)
      if !ranges.isEmpty {
        resourceFlag = resourceFlagOne(lineage: lineage)
        sourceElements.append(contentsOf: ranges)
      }
      let routes = try PortalSP2Tree.children(named: "ROUTE", of: securedRoutes)
      if routes.count > 1 {
        resourceFlag = resourceFlagOne(lineage: lineage)
      }
      sourceElements.append(contentsOf: routes)
    }

    if let securedRange {
      let ranges = try PortalSP2Tree.children(named: "RANGE", of: securedRange)
      if !ranges.isEmpty {
        name = try PortalSP2Value.text(
          try PortalSP2Tree.attribute(named: "name", of: securedRange),
          lineage: lineage
        )
      }
      if ranges.count == 1 {
        resourceFlag = resourceFlagOne(lineage: lineage)
        sourceElements.append(ranges[0])
      }
    }

    if let securedRoute {
      let routes = try PortalSP2Tree.children(named: "ROUTE", of: securedRoute)
      if routes.count == 1 { sourceElements.append(routes[0]) }
    }

    var routes: [VendorCharonStartRouteCandidate] = []
    for element in sourceElements {
      guard
        let address = try PortalSP2Tree.attribute(named: "addr", of: element),
        let route = try directRoute(address, lineage: lineage)
      else {
        return PortalSP2RouteMapping(
          resourceFlag: resourceFlag,
          name: name,
          routes: nil
        )
      }
      routes.append(route)
    }
    return PortalSP2RouteMapping(
      resourceFlag: resourceFlag,
      name: name,
      routes: routes
    )
  }

  private static func empty(
    lineage: VendorCharonStartLineage
  ) -> PortalSP2RouteMapping {
    PortalSP2RouteMapping(
      resourceFlag: PortalSP2Value.generatedInteger(0, lineage: lineage),
      name: PortalSP2Value.generatedText([], lineage: lineage),
      routes: []
    )
  }

  private static func resourceFlagOne(
    lineage: VendorCharonStartLineage
  ) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: 1,
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  /// This slice intentionally excludes `start-end` expansion. A hyphen or any
  /// malformed IPv4/CIDR leaves the tunnel's whole routes field missing so no
  /// partial route set can pass readiness.
  private static func directRoute(
    _ address: PortalSP2Scalar,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartRouteCandidate? {
    try address.withBytes { bytes in
      guard !bytes.isEmpty, !bytes.contains(0), !bytes.contains(0x2d) else {
        return nil
      }
      let slashIndices = bytes.indices.filter { bytes[$0] == 0x2f }
      guard slashIndices.count <= 1 else { return nil }
      let addressEnd = slashIndices.first ?? bytes.count
      guard validIPv4(bytes, range: 0..<addressEnd) else { return nil }

      let prefix: Int32
      if let slash = slashIndices.first {
        guard let parsed = decimal(bytes, range: (slash + 1)..<bytes.count), parsed <= 32 else {
          return nil
        }
        prefix = parsed
      } else {
        prefix = 32
      }
      let network = VendorCharonStartTextValue(
        value: try PortalSP2SliceTextMaterial(address, range: 0..<addressEnd),
        source: .authenticatedPortalResource,
        lineage: lineage
      )
      let routePrefix = VendorCharonStartPrefixValue(
        value: .integer(prefix),
        source: .authenticatedPortalResource,
        lineage: lineage
      )
      return VendorCharonStartRouteCandidate(network: network, prefix: routePrefix)
    }
  }

  private static func validIPv4(
    _ bytes: UnsafeRawBufferPointer,
    range: Range<Int>
  ) -> Bool {
    guard !range.isEmpty else { return false }
    var octetStart = range.lowerBound
    var octets = 0
    for index in range.lowerBound...range.upperBound {
      if index == range.upperBound || bytes[index] == 0x2e {
        let part = octetStart..<index
        guard !part.isEmpty, part.count <= 3,
          !(part.count > 1 && bytes[part.lowerBound] == 0x30),
          let value = decimal(bytes, range: part), value <= 255
        else { return false }
        octets += 1
        octetStart = index + 1
      }
    }
    return octets == 4
  }

  private static func decimal(
    _ bytes: UnsafeRawBufferPointer,
    range: Range<Int>
  ) -> Int32? {
    guard !range.isEmpty else { return nil }
    var value: Int32 = 0
    for index in range {
      let byte = bytes[index]
      guard (0x30...0x39).contains(byte) else { return nil }
      let (scaled, overflow1) = value.multipliedReportingOverflow(by: 10)
      let (next, overflow2) = scaled.addingReportingOverflow(Int32(byte - 0x30))
      guard !overflow1, !overflow2 else { return nil }
      value = next
    }
    return value
  }
}
