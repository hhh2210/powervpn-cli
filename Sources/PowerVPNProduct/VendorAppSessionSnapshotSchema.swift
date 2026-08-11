import PowerVPNCore

enum VendorAppSessionSnapshotSchema {
  static let rootKeys: Set<String> = ["common", "rpc", "tunnels", "type"]
  static let commonKeys: Set<String> = [
    "authport", "dns", "dnsv6", "esp", "gateway", "ike", "ike_life_time", "ike_port",
    "ipsec_life_time", "majorVersion", "name", "natt_port", "psk", "sessionid", "status",
    "subnet", "tunnelnameV4", "vip", "vipv6",
  ]
  static let tunnelKeys: Set<String> = [
    "authority", "cmd", "display", "enc", "excludes", "family", "icon", "mapid", "name",
    "negotiate-mode", "notice", "rflag", "routes", "status", "tunnel-name",
  ]
  static let routeKeys: Set<String> = ["family", "mask", "net", "prfix"]

  static func validate(
    root: [String: VendorAppSessionLogNode],
    bytes: UnsafeRawBufferPointer
  ) throws {
    try requireExactKeys(root, expected: rootKeys)
    guard
      try scalarEquals(
        root, "type", VendorCharonStartContract.requestType, style: .bare, bytes: bytes),
      try scalarEquals(
        root, "rpc", VendorCharonStartContract.requestRPC, style: .quoted, bytes: bytes),
      let common = root["common"]?.dictionary,
      let tunnels = root["tunnels"]?.array,
      tunnels.count == 2
    else { throw VendorAppSessionSnapshotError.malformed }
    try validateCommon(common, bytes: bytes)

    var sawLogin21 = false
    var sawLogin52 = false
    for node in tunnels {
      guard let tunnel = node.dictionary else {
        throw VendorAppSessionSnapshotError.malformed
      }
      try validateTunnel(tunnel, bytes: bytes)
      if try scalarEquals(tunnel, "tunnel-name", "login21", style: .bare, bytes: bytes) {
        guard !sawLogin21 else { throw VendorAppSessionSnapshotError.malformed }
        sawLogin21 = true
      } else if try scalarEquals(
        tunnel, "tunnel-name", "login52", style: .bare, bytes: bytes)
      {
        guard !sawLogin52 else { throw VendorAppSessionSnapshotError.malformed }
        sawLogin52 = true
      } else {
        throw VendorAppSessionSnapshotError.malformed
      }
    }
    guard sawLogin21, sawLogin52 else {
      throw VendorAppSessionSnapshotError.resourceUnavailable
    }
  }

  static func scalarRange(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    bytes: UnsafeRawBufferPointer
  ) throws -> Range<Int> {
    guard let range = dictionary[key]?.scalarRange,
      range.lowerBound >= 0,
      range.upperBound <= bytes.count,
      range.count <= VendorCharonStartValidator.maximumTextBytes
    else { throw VendorAppSessionSnapshotError.malformed }
    return range
  }

  static func decimal(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    bytes: UnsafeRawBufferPointer
  ) throws -> Int32 {
    guard let scalar = dictionary[key]?.scalar, scalar.style == .bare else {
      throw VendorAppSessionSnapshotError.malformed
    }
    let range = try scalarRange(dictionary, key, bytes: bytes)
    guard !range.isEmpty else { throw VendorAppSessionSnapshotError.malformed }
    var cursor = range.lowerBound
    let negative = bytes[cursor] == 0x2D
    if negative { cursor += 1 }
    guard cursor < range.upperBound else { throw VendorAppSessionSnapshotError.malformed }
    if bytes[cursor] == 0x30, cursor + 1 != range.upperBound {
      throw VendorAppSessionSnapshotError.malformed
    }
    var magnitude: Int64 = 0
    let limit: Int64 = negative ? 2_147_483_648 : 2_147_483_647
    while cursor < range.upperBound {
      let byte = bytes[cursor]
      guard (0x30...0x39).contains(byte) else {
        throw VendorAppSessionSnapshotError.malformed
      }
      let digit = Int64(byte - 0x30)
      guard magnitude <= (limit - digit) / 10 else {
        throw VendorAppSessionSnapshotError.malformed
      }
      magnitude = magnitude * 10 + digit
      cursor += 1
    }
    guard !negative || magnitude != 0,
      let value = Int32(exactly: negative ? -magnitude : magnitude)
    else { throw VendorAppSessionSnapshotError.malformed }
    return value
  }

  static func scalarEquals(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    _ expected: String,
    style: VendorAppSessionLogScalar.Style? = nil,
    bytes: UnsafeRawBufferPointer
  ) throws -> Bool {
    guard let scalar = dictionary[key]?.scalar, style == nil || scalar.style == style else {
      throw VendorAppSessionSnapshotError.malformed
    }
    let range = try scalarRange(dictionary, key, bytes: bytes)
    let expectedBytes = Array(expected.utf8)
    guard range.count == expectedBytes.count else { return false }
    return expectedBytes.enumerated().allSatisfy { offset, byte in
      bytes[range.lowerBound + offset] == byte
    }
  }

  private static func validateCommon(
    _ common: [String: VendorAppSessionLogNode],
    bytes: UnsafeRawBufferPointer
  ) throws {
    try requireExactKeys(common, expected: commonKeys)
    for key in [
      "authport", "ike_life_time", "ike_port", "ipsec_life_time", "majorVersion",
      "natt_port", "status",
    ] {
      _ = try decimal(common, key, bytes: bytes)
    }
    for key in ["esp", "gateway", "ike", "sessionid"] {
      try requireText(common, key, style: .quoted, allowsEmpty: false, bytes: bytes)
    }
    for key in ["dns", "dnsv6", "subnet", "vip", "vipv6"] {
      try requireText(common, key, style: .quoted, allowsEmpty: true, bytes: bytes)
    }
    for key in ["name", "psk", "tunnelnameV4"] {
      try requireText(common, key, style: .bare, allowsEmpty: false, bytes: bytes)
    }
  }

  private static func validateTunnel(
    _ tunnel: [String: VendorAppSessionLogNode],
    bytes: UnsafeRawBufferPointer
  ) throws {
    try requireExactKeys(tunnel, expected: tunnelKeys)
    for key in ["authority", "display", "family", "negotiate-mode", "rflag", "status"] {
      _ = try decimal(tunnel, key, bytes: bytes)
    }
    for key in ["cmd", "mapid"] {
      try requireText(tunnel, key, style: .quoted, allowsEmpty: false, bytes: bytes)
    }
    for key in ["icon", "name", "notice"] {
      try requireText(tunnel, key, style: .quoted, allowsEmpty: true, bytes: bytes)
    }
    for key in ["enc", "tunnel-name"] {
      try requireText(tunnel, key, style: .bare, allowsEmpty: false, bytes: bytes)
    }
    guard let excludes = tunnel["excludes"]?.array, excludes.isEmpty,
      let routes = tunnel["routes"]?.array, !routes.isEmpty
    else { throw VendorAppSessionSnapshotError.malformed }
    for node in routes {
      guard let route = node.dictionary else {
        throw VendorAppSessionSnapshotError.malformed
      }
      try requireExactKeys(route, expected: routeKeys)
      _ = try decimal(route, "family", bytes: bytes)
      _ = try decimal(route, "prfix", bytes: bytes)
      try requireText(route, "mask", style: .quoted, allowsEmpty: false, bytes: bytes)
      try requireText(route, "net", style: .quoted, allowsEmpty: false, bytes: bytes)
    }
  }

  private static func requireText(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    style: VendorAppSessionLogScalar.Style,
    allowsEmpty: Bool,
    bytes: UnsafeRawBufferPointer
  ) throws {
    guard let scalar = dictionary[key]?.scalar, scalar.style == style else {
      throw VendorAppSessionSnapshotError.malformed
    }
    let range = try scalarRange(dictionary, key, bytes: bytes)
    guard allowsEmpty || !range.isEmpty else {
      throw VendorAppSessionSnapshotError.malformed
    }
  }

  private static func requireExactKeys(
    _ dictionary: [String: VendorAppSessionLogNode],
    expected: Set<String>
  ) throws {
    guard Set(dictionary.keys) == expected else {
      throw VendorAppSessionSnapshotError.malformed
    }
  }
}
