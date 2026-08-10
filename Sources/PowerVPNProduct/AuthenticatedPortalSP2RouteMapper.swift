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

    var outputRoutes: [VendorCharonStartRouteCandidate] = []
    for element in sourceElements {
      guard
        let address = try PortalSP2Tree.attribute(named: "addr", of: element),
        let mappedRoutes = try mapAddress(address, lineage: lineage)
      else {
        return PortalSP2RouteMapping(
          resourceFlag: resourceFlag,
          name: name,
          routes: nil
        )
      }
      outputRoutes.append(contentsOf: mappedRoutes)
    }
    return PortalSP2RouteMapping(
      resourceFlag: resourceFlag,
      name: name,
      routes: outputRoutes
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

  private static func mapAddress(
    _ address: PortalSP2Scalar,
    lineage: VendorCharonStartLineage
  ) throws -> [VendorCharonStartRouteCandidate]? {
    if try address.withBytes({ $0.contains(0x2d) }) {
      return try PortalSP2IPv4RangeMapper.routes(address, lineage: lineage)
    }
    return try directRoute(address, lineage: lineage).map { [$0] }
  }

  private static func directRoute(
    _ address: PortalSP2Scalar,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartRouteCandidate? {
    try address.withBytes { bytes in
      guard !bytes.isEmpty, !bytes.contains(0) else {
        return nil
      }
      let slashIndices = bytes.indices.filter { bytes[$0] == 0x2f }
      guard slashIndices.count <= 1 else { return nil }
      let addressEnd = slashIndices.first ?? bytes.count
      guard PortalSP2IPv4.parse(bytes, range: 0..<addressEnd) != nil else { return nil }

      let prefix: Int32
      if let slash = slashIndices.first {
        guard
          let parsed = PortalSP2IPv4.decimal(bytes, range: (slash + 1)..<bytes.count),
          parsed <= 32
        else {
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
}
