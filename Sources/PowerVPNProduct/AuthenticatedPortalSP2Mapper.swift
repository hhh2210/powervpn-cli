import PowerVPNCore
import PowerVPNPortal

struct AuthenticatedPortalSP2MappedTunnel {
  let displayName: String
  let sourceTunnelIndex: Int
  let encodedTunnelIndex: Int
}

struct AuthenticatedPortalSP2MappedResource {
  let validation: VendorCharonStartValidation
  let tunnels: [AuthenticatedPortalSP2MappedTunnel]
}

enum AuthenticatedPortalSP2Mapper {
  static func mappedResource(
    _ resource: AuthenticatedPortalResourceElement,
    majorVersion: Int32,
    gateway: any VendorCharonStartTextMaterial,
    lineage: VendorCharonStartLineage = VendorCharonStartLineage()
  ) throws -> AuthenticatedPortalSP2MappedResource {
    let tunnelElements = try PortalSP2Tree.children(named: "TUNNEL", of: resource)
    guard !tunnelElements.isEmpty else {
      throw AuthenticatedPortalSnapshotMappingError.missingTunnelElement
    }
    let commonIKE = try commonIKE(resource: resource, tunnels: tunnelElements)
    var mappedTunnels: [VendorCharonStartTunnelCandidate] = []
    var descriptors: [AuthenticatedPortalSP2MappedTunnel] = []
    for (sourceTunnelIndex, element) in tunnelElements.enumerated() {
      guard let tunnel = try mapTunnel(element, resource: resource, lineage: lineage) else {
        continue
      }
      descriptors.append(
        AuthenticatedPortalSP2MappedTunnel(
          displayName: try PortalSP2Tree.displayName(of: element),
          sourceTunnelIndex: sourceTunnelIndex,
          encodedTunnelIndex: mappedTunnels.count
        ))
      mappedTunnels.append(tunnel)
    }
    let coreCandidate = VendorCharonStartCandidate(
      lineage: lineage,
      common: try common(
        from: commonIKE,
        resource: resource,
        majorVersion: majorVersion,
        gateway: gateway,
        lineage: lineage
      ),
      tunnels: mappedTunnels
    )
    return AuthenticatedPortalSP2MappedResource(
      validation: VendorCharonStartValidator.validate(coreCandidate),
      tunnels: descriptors
    )
  }

  private static func commonIKE(
    resource: AuthenticatedPortalResourceElement,
    tunnels: [AuthenticatedPortalResourceElement]
  ) throws -> AuthenticatedPortalResourceElement? {
    if let firstTunnel = tunnels.first,
      let ike = try PortalSP2Tree.child(named: "IKE", of: firstTunnel)
    {
      return ike
    }
    return try PortalSP2Tree.child(named: "IKE", of: resource)
  }
  private static func common(
    from ike: AuthenticatedPortalResourceElement?,
    resource: AuthenticatedPortalResourceElement,
    majorVersion: Int32,
    gateway: any VendorCharonStartTextMaterial,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartCommonCandidate {
    let gateway = VendorCharonStartTextValue(
      value: gateway,
      source: .authenticatedPortalOrigin,
      lineage: lineage
    )
    // Official `common.vip` resolution first chases
    // IKE→EXTENSIONS→PRIVATE-IP@addr, then falls back only when that scalar
    // is nil to portal property `vip` (0x1000687f3–0x1000688f8). The
    // property is populated by the portal callback's major=="1" branch from
    // RESOURCE_LIST→NC_RESOURCE→PRIVATE-IP@addr
    // (0x1000aa70c–0x1000aa894). Resolve both sources independently and
    // preserve that extension-first, property-second precedence.
    let extensions = try ike.flatMap { try PortalSP2Tree.child(named: "EXTENSIONS", of: $0) }
    let extensionPrivateIP = try extensions.flatMap {
      try PortalSP2Tree.child(named: "PRIVATE-IP", of: $0)
    }
    let extensionAddr = try extensionPrivateIP.flatMap {
      try PortalSP2Tree.attribute(named: "addr", of: $0)
    }
    let resourcePrivateIP = try PortalSP2Tree.child(named: "PRIVATE-IP", of: resource)
    let resourceAddr = try resourcePrivateIP.flatMap {
      try PortalSP2Tree.attribute(named: "addr", of: $0)
    }
    let vipAddress = extensionAddr ?? resourceAddr
    guard let ike else {
      return VendorCharonStartCommonCandidate(
        vip: try PortalSP2Value.text(vipAddress, lineage: lineage),
        gateway: gateway,
        majorVersion: PortalSP2Value.metadataInteger(majorVersion, lineage: lineage)
      )
    }
    let client = try PortalSP2Tree.child(named: "CLIENT", of: ike)
    let server = try PortalSP2Tree.child(named: "SERVER", of: ike)
    let psk = try PortalSP2Tree.child(named: "PSK", of: ike)
    let ikeProposal = try proposal(
      in: ike,
      root: "ISAKMP-SA",
      suffix: [0x2d] + Array("modp1024".utf8),
      lifetimePath: "common.ike_life_time",
      lineage: lineage
    )
    let espProposal = try proposal(
      in: ike,
      root: "IPSEC-SA",
      suffix: [],
      lifetimePath: "common.ipsec_life_time",
      lineage: lineage
    )
    return VendorCharonStartCommonCandidate(
      sessionID: try PortalSP2Value.text(
        try client.flatMap { try PortalSP2Tree.attribute(named: "id", of: $0) },
        lineage: lineage
      ),
      vip: try PortalSP2Value.text(vipAddress, lineage: lineage),
      gateway: gateway,
      ikePort: try PortalSP2Value.integer(
        try server.flatMap { try PortalSP2Tree.attribute(named: "port", of: $0) },
        path: "common.ike_port",
        lineage: lineage
      ),
      majorVersion: PortalSP2Value.metadataInteger(majorVersion, lineage: lineage),
      ike: ikeProposal.suite,
      esp: espProposal.suite,
      psk: try PortalSP2Value.text(
        try psk.flatMap { try PortalSP2Tree.attribute(named: "key", of: $0) },
        lineage: lineage
      ),
      ikeLifetime: ikeProposal.lifetime,
      ipsecLifetime: espProposal.lifetime
    )
  }

  private static func proposal(
    in ike: AuthenticatedPortalResourceElement,
    root: String,
    suffix: [UInt8],
    lifetimePath: String,
    lineage: VendorCharonStartLineage
  ) throws -> PortalSP2Proposal {
    let transform = try PortalSP2Tree.descendant(
      from: ike,
      path: [root, "PROPOSAL", "TRANSFORMS", "TRANSFORM"]
    )
    guard let transform else { return PortalSP2Proposal(suite: nil, lifetime: nil) }
    let enc = try PortalSP2Tree.attribute(named: "enc", of: transform)
    let hash = try PortalSP2Tree.attribute(named: "hash", of: transform)
    let lifetime = try PortalSP2Value.integer(
      try PortalSP2Tree.attribute(named: "life-time", of: transform),
      path: lifetimePath,
      lineage: lineage
    )
    guard let enc, let hash,
      try enc.byteCount > 0, try hash.byteCount > 0
    else {
      return PortalSP2Proposal(suite: nil, lifetime: lifetime)
    }
    let encMaterial = try proposalComponent(
      enc,
      nullDefault: Array("aes128".utf8)
    )
    let hashMaterial = try proposalComponent(
      hash,
      nullDefault: Array("md5".utf8)
    )
    var components: [any VendorCharonStartTextMaterial] = [
      encMaterial,
      PortalSP2ConstantTextMaterial([0x2d]),
      hashMaterial,
    ]
    if !suffix.isEmpty {
      components.append(PortalSP2ConstantTextMaterial(suffix))
    }
    let suite = VendorCharonStartTextValue(
      value: try PortalSP2ComposedTextMaterial(components),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
    return PortalSP2Proposal(suite: suite, lifetime: lifetime)
  }

  private static func proposalComponent(
    _ scalar: PortalSP2Scalar,
    nullDefault: [UInt8]
  ) throws -> any VendorCharonStartTextMaterial {
    if try scalar.bytesEqual(Array("null".utf8)) {
      return PortalSP2ConstantTextMaterial(nullDefault)
    }
    return try PortalSP2BorrowedTextMaterial(scalar)
  }

  private static func mapTunnel(
    _ tunnel: AuthenticatedPortalResourceElement,
    resource: AuthenticatedPortalResourceElement,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartTunnelCandidate? {
    let resourceStatus = try PortalSP2Tree.attribute(named: "status", of: resource)
    let statusScalar: PortalSP2Scalar?
    if let resourceStatus {
      statusScalar = resourceStatus
    } else {
      statusScalar = try PortalSP2Tree.attribute(named: "status", of: tunnel)
    }
    guard let statusScalar else { return nil }
    let status = try PortalSP2Value.integer(
      statusScalar,
      path: "tunnels[].status",
      lineage: lineage
    )!
    guard status.value != 0 else { return nil }
    let ike = try PortalSP2Tree.child(named: "IKE", of: tunnel)
    let ikeExtensions = try ike.flatMap {
      try PortalSP2Tree.child(named: "EXTENSIONS", of: $0)
    }
    let extensions: AuthenticatedPortalResourceElement?
    if let ikeExtensions {
      extensions = ikeExtensions
    } else {
      extensions = try PortalSP2Tree.child(named: "EXTENSIONS", of: tunnel)
    }
    let routeMapping = try AuthenticatedPortalSP2RouteMapper.map(
      extensions: extensions,
      lineage: lineage
    )
    let authorityScalar = try PortalSP2Tree.attribute(named: "authority", of: tunnel)
    let familyScalar = try ike.flatMap {
      try PortalSP2Tree.attribute(named: "family", of: $0)
    }
    let resourceMapID = try PortalSP2Tree.attribute(named: "mapid", of: resource)
    let mapIDScalar: PortalSP2Scalar?
    if let resourceMapID {
      mapIDScalar = resourceMapID
    } else {
      mapIDScalar = try PortalSP2Tree.attribute(named: "mapid", of: tunnel)
    }
    return VendorCharonStartTunnelCandidate(
      authority: try PortalSP2Value.integer(
        authorityScalar,
        path: "tunnels[].authority",
        lineage: lineage
      ) ?? PortalSP2Value.generatedInteger(1, lineage: lineage),
      status: status,
      tunnelName: try PortalSP2Value.text(
        try PortalSP2Tree.attribute(named: "tunnel-name", of: tunnel),
        lineage: lineage
      ),
      family: try PortalSP2Value.integer(
        familyScalar,
        path: "tunnels[].family",
        lineage: lineage
      ) ?? PortalSP2Value.generatedInteger(4, lineage: lineage),
      resourceFlag: routeMapping.resourceFlag,
      name: routeMapping.name,
      routes: routeMapping.routes,
      mapID: try PortalSP2Value.text(mapIDScalar, lineage: lineage),
      negotiateMode: try PortalSP2Value.integer(
        try PortalSP2Tree.attribute(named: "negotiate-mode", of: tunnel),
        path: "tunnels[].negotiate-mode",
        lineage: lineage
      )
    )
  }
}

private struct PortalSP2Proposal {
  let suite: VendorCharonStartTextValue?
  let lifetime: VendorCharonStartIntegerValue?
}
