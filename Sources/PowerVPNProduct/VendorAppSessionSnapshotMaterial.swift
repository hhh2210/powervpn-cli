import PowerVPNCore
import PowerVPNPortal

final class VendorAppSessionSnapshotMaterial: @unchecked Sendable {
  static let resourceName = "login21"
  static let resourceHandle = "vendor_once:login21"

  let candidate: VendorCharonStartCandidate
  let summary = ProductResourceSummary(
    handle: resourceHandle,
    displayName: resourceName
  )
  private let buffers: [SecureBytes]
  private let sourceSeal: VendorAppSessionSourceSeal?

  init(
    root: VendorAppSessionLogNode,
    bytes: UnsafeRawBufferPointer,
    sourceSeal: VendorAppSessionSourceSeal? = nil
  ) throws {
    var builder = VendorAppSessionCandidateBuilder(bytes: bytes)
    candidate = try builder.build(root: root)
    buffers = builder.buffers
    self.sourceSeal = sourceSeal
  }

  var validation: VendorCharonStartValidation {
    VendorCharonStartValidator.validate(candidate)
  }

  func erase() {
    for buffer in buffers { buffer.erase() }
  }

  var isErased: Bool {
    buffers.allSatisfy { $0.count == 0 }
  }

  var sourceIsCurrent: Bool {
    sourceSeal?.isCurrent() ?? true
  }

  deinit {
    erase()
  }
}

private struct VendorAppSessionCandidateBuilder {
  private(set) var buffers: [SecureBytes] = []
  private let bytes: UnsafeRawBufferPointer
  private let source = VendorCharonStartMaterialSource.installedVendorOnboarding

  init(bytes: UnsafeRawBufferPointer) {
    self.bytes = bytes
  }

  mutating func build(root: VendorAppSessionLogNode) throws -> VendorCharonStartCandidate {
    let root = try dictionary(root)
    try VendorAppSessionSnapshotSchema.validate(root: root, bytes: bytes)
    guard let commonNode = root["common"],
      let tunnelsNode = root["tunnels"]
    else { throw VendorAppSessionSnapshotError.malformed }
    let common = try dictionary(commonNode)
    let tunnels = try array(tunnelsNode)

    var selected: [String: VendorAppSessionLogNode]?
    var selectedCount = 0
    for tunnelNode in tunnels {
      let tunnel = try dictionary(tunnelNode)
      if try VendorAppSessionSnapshotSchema.scalarEquals(
        tunnel,
        "tunnel-name",
        VendorAppSessionSnapshotMaterial.resourceName,
        style: .bare,
        bytes: bytes
      ) {
        selected = tunnel
        selectedCount += 1
      }
    }
    guard selectedCount == 1, let selected else {
      throw VendorAppSessionSnapshotError.resourceUnavailable
    }

    let lineage = VendorCharonStartLineage()
    let commonCandidate = try VendorCharonStartCommonCandidate(
      sessionID: text(common, "sessionid", lineage: lineage),
      vip: optionalText(common, "vip", lineage: lineage),
      vipv6: optionalText(common, "vipv6", lineage: lineage),
      gateway: text(common, "gateway", lineage: lineage),
      ikePort: integer(common, "ike_port", lineage: lineage),
      majorVersion: integer(common, "majorVersion", lineage: lineage),
      ike: text(common, "ike", lineage: lineage),
      esp: text(common, "esp", lineage: lineage),
      psk: text(common, "psk", lineage: lineage),
      ikeLifetime: integer(common, "ike_life_time", lineage: lineage),
      ipsecLifetime: integer(common, "ipsec_life_time", lineage: lineage)
    )
    let tunnelCandidate = try buildTunnel(selected, lineage: lineage)
    return VendorCharonStartCandidate(
      lineage: lineage,
      common: commonCandidate,
      tunnels: [tunnelCandidate]
    )
  }

  private mutating func buildTunnel(
    _ tunnel: [String: VendorAppSessionLogNode],
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartTunnelCandidate {
    let status = try decimal(tunnel, "status")
    guard status != 0 else { throw VendorAppSessionSnapshotError.resourceUnavailable }
    let routeNodes = try array(required(tunnel, "routes"))
    let routes = try routeNodes.map { node in
      let route = try dictionary(node)
      return VendorCharonStartRouteCandidate(
        network: try text(route, "net", lineage: lineage),
        prefix: VendorCharonStartPrefixValue(
          value: .integer(try decimal(route, "prfix")),
          source: source,
          lineage: lineage
        )
      )
    }
    return VendorCharonStartTunnelCandidate(
      authority: try integer(tunnel, "authority", lineage: lineage),
      status: VendorCharonStartIntegerValue(
        value: status,
        source: source,
        lineage: lineage
      ),
      tunnelName: try text(tunnel, "tunnel-name", lineage: lineage),
      family: try integer(tunnel, "family", lineage: lineage),
      resourceFlag: try integer(tunnel, "rflag", lineage: lineage),
      name: try text(tunnel, "name", lineage: lineage, allowsEmpty: true),
      routes: routes,
      mapID: try text(tunnel, "mapid", lineage: lineage),
      negotiateMode: try optionalInteger(tunnel, "negotiate-mode", lineage: lineage)
    )
  }

  private mutating func text(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    lineage: VendorCharonStartLineage,
    allowsEmpty: Bool = false
  ) throws -> VendorCharonStartTextValue {
    let range = try VendorAppSessionSnapshotSchema.scalarRange(
      dictionary, key, bytes: bytes)
    guard allowsEmpty || !range.isEmpty else {
      throw VendorAppSessionSnapshotError.malformed
    }
    let start = bytes.baseAddress?.advanced(by: range.lowerBound)
    let storage = try SecureBytes(
      copying: UnsafeRawBufferPointer(start: start, count: range.count)
    )
    buffers.append(storage)
    return VendorCharonStartTextValue(
      value: VendorAppSessionText(bytes: storage),
      source: source,
      lineage: lineage
    )
  }

  private mutating func optionalText(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartTextValue? {
    guard dictionary[key] != nil else { return nil }
    let range = try VendorAppSessionSnapshotSchema.scalarRange(
      dictionary, key, bytes: bytes)
    return range.isEmpty ? nil : try text(dictionary, key, lineage: lineage)
  }

  private func integer(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: try decimal(dictionary, key),
      source: source,
      lineage: lineage
    )
  }

  private func optionalInteger(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartIntegerValue? {
    guard dictionary[key] != nil else { return nil }
    return try integer(dictionary, key, lineage: lineage)
  }

  private func decimal(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String
  ) throws -> Int32 {
    try VendorAppSessionSnapshotSchema.decimal(dictionary, key, bytes: bytes)
  }

  private func required(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String
  ) throws -> VendorAppSessionLogNode {
    guard let value = dictionary[key] else {
      throw VendorAppSessionSnapshotError.malformed
    }
    return value
  }

  private func dictionary(
    _ node: VendorAppSessionLogNode
  ) throws -> [String: VendorAppSessionLogNode] {
    guard let dictionary = node.dictionary else {
      throw VendorAppSessionSnapshotError.malformed
    }
    return dictionary
  }

  private func array(
    _ node: VendorAppSessionLogNode
  ) throws -> [VendorAppSessionLogNode] {
    guard let array = node.array else { throw VendorAppSessionSnapshotError.malformed }
    return array
  }

}
