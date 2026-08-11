import PowerVPNCore

enum VendorAppSessionSnapshotSchema {

  static func validate(
    root: [String: VendorAppSessionLogNode],
    bytes: UnsafeRawBufferPointer
  ) throws {
    try requireExactFields(root, fields: rootFields, expected: rootKeys)
    guard
      try requiredScalarEquals(
        root, field: rootFields[0], expected: VendorCharonStartContract.requestType,
        style: .bare, bytes: bytes)
    else { throw VendorAppSessionSnapshotError.malformed }
    guard
      try requiredScalarEquals(
        root, field: rootFields[1], expected: VendorCharonStartContract.requestRPC,
        style: .quoted, bytes: bytes)
    else { throw VendorAppSessionSnapshotError.malformed }
    let common = try requiredDictionary(root, field: rootFields[2])
    let tunnels = try requiredArray(root, field: rootFields[3])
    guard tunnels.count == 2 else {
      throw VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
    }
    try validateCommon(common, bytes: bytes)

    var sawLogin21 = false
    var sawLogin52 = false
    for node in tunnels {
      guard let tunnel = node.dictionary else {
        throw VendorAppSessionSnapshotError.requiredFieldWrongType(.tunnelRecord)
      }
      try validateTunnel(tunnel, bytes: bytes)
      if try scalarEquals(tunnel, "tunnel-name", "login21", style: .bare, bytes: bytes) {
        guard !sawLogin21 else {
          throw VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
        }
        sawLogin21 = true
      } else if try scalarEquals(
        tunnel, "tunnel-name", "login52", style: .bare, bytes: bytes)
      {
        guard !sawLogin52 else {
          throw VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
        }
        sawLogin52 = true
      } else {
        throw VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
      }
    }
    guard sawLogin21, sawLogin52 else {
      throw VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
    }
  }

  static func scalarRange(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    bytes: UnsafeRawBufferPointer
  ) throws -> Range<Int> {
    guard let range = dictionary[key]?.scalarRange else {
      throw VendorAppSessionSnapshotError.malformed
    }
    return try validatedRange(range, bytes: bytes)
  }

  static func decimal(
    _ dictionary: [String: VendorAppSessionLogNode],
    _ key: String,
    bytes: UnsafeRawBufferPointer
  ) throws -> Int32 {
    guard let scalar = dictionary[key]?.scalar, scalar.style == .bare else {
      throw VendorAppSessionSnapshotError.malformed
    }
    return try decimalValue(try validatedRange(scalar.range, bytes: bytes), bytes: bytes)
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
    let range = try validatedRange(scalar.range, bytes: bytes)
    return equal(bytes, range: range, expected: expected)
  }

  private static func validateCommon(
    _ common: [String: VendorAppSessionLogNode],
    bytes: UnsafeRawBufferPointer
  ) throws {
    try requireExactFields(common, fields: commonFields, expected: commonKeys)
    for index in [0, 6, 7, 8, 9, 11, 14] {
      _ = try requiredDecimal(common, field: commonFields[index], bytes: bytes)
    }
    for index in [3, 4, 5, 13] {
      try requiredText(
        common, field: commonFields[index], style: .quoted, allowsEmpty: false, bytes: bytes)
    }
    for index in [1, 2, 15, 17, 18] {
      try requiredText(
        common, field: commonFields[index], style: .quoted, allowsEmpty: true, bytes: bytes)
    }
    for index in [10, 12, 16] {
      try requiredText(
        common, field: commonFields[index], style: .bare, allowsEmpty: false, bytes: bytes)
    }
  }

  private static func validateTunnel(
    _ tunnel: [String: VendorAppSessionLogNode],
    bytes: UnsafeRawBufferPointer
  ) throws {
    try requireExactFields(tunnel, fields: tunnelFields, expected: tunnelKeys)
    for index in [0, 2, 5, 9, 11, 13] {
      _ = try requiredDecimal(tunnel, field: tunnelFields[index], bytes: bytes)
    }
    for index in [1, 7] {
      try requiredText(
        tunnel, field: tunnelFields[index], style: .quoted, allowsEmpty: false, bytes: bytes)
    }
    for index in [6, 8, 10] {
      try requiredText(
        tunnel, field: tunnelFields[index], style: .quoted, allowsEmpty: true, bytes: bytes)
    }
    for index in [3, 14] {
      try requiredText(
        tunnel, field: tunnelFields[index], style: .bare, allowsEmpty: false, bytes: bytes)
    }
    let excludes = try requiredArray(tunnel, field: tunnelFields[4])
    let routes = try requiredArray(tunnel, field: tunnelFields[12])
    guard excludes.isEmpty, !routes.isEmpty else {
      throw VendorAppSessionSnapshotError.malformed
    }
    for node in routes {
      guard let route = node.dictionary else {
        throw VendorAppSessionSnapshotError.requiredFieldWrongType(.routeRecord)
      }
      try requireExactFields(route, fields: routeFields, expected: routeKeys)
      _ = try requiredDecimal(route, field: routeFields[0], bytes: bytes)
      try requiredText(
        route, field: routeFields[1], style: .quoted, allowsEmpty: false, bytes: bytes)
      try requiredText(
        route, field: routeFields[2], style: .quoted, allowsEmpty: false, bytes: bytes)
      _ = try requiredDecimal(route, field: routeFields[3], bytes: bytes)
    }
  }

  private static func requiredDictionary(
    _ dictionary: [String: VendorAppSessionLogNode],
    field: Field
  ) throws -> [String: VendorAppSessionLogNode] {
    guard let value = dictionary[field.key] else {
      throw VendorAppSessionSnapshotError.requiredFieldMissing(field.diagnostic)
    }
    guard let value = value.dictionary else {
      throw VendorAppSessionSnapshotError.requiredFieldWrongType(field.diagnostic)
    }
    return value
  }

  private static func requiredArray(
    _ dictionary: [String: VendorAppSessionLogNode],
    field: Field
  ) throws -> [VendorAppSessionLogNode] {
    guard let value = dictionary[field.key] else {
      throw VendorAppSessionSnapshotError.requiredFieldMissing(field.diagnostic)
    }
    guard let value = value.array else {
      throw VendorAppSessionSnapshotError.requiredFieldWrongType(field.diagnostic)
    }
    return value
  }

  private static func requiredScalar(
    _ dictionary: [String: VendorAppSessionLogNode],
    field: Field,
    style: VendorAppSessionLogScalar.Style
  ) throws -> VendorAppSessionLogScalar {
    guard let value = dictionary[field.key] else {
      throw VendorAppSessionSnapshotError.requiredFieldMissing(field.diagnostic)
    }
    guard let scalar = value.scalar, scalar.style == style else {
      throw VendorAppSessionSnapshotError.requiredFieldWrongType(field.diagnostic)
    }
    return scalar
  }

  private static func requiredDecimal(
    _ dictionary: [String: VendorAppSessionLogNode],
    field: Field,
    bytes: UnsafeRawBufferPointer
  ) throws -> Int32 {
    let scalar = try requiredScalar(dictionary, field: field, style: .bare)
    do {
      return try decimalValue(
        try validatedRange(scalar.range, bytes: bytes),
        bytes: bytes
      )
    } catch {
      throw VendorAppSessionSnapshotError.requiredFieldWrongType(field.diagnostic)
    }
  }

  private static func requiredText(
    _ dictionary: [String: VendorAppSessionLogNode],
    field: Field,
    style: VendorAppSessionLogScalar.Style,
    allowsEmpty: Bool,
    bytes: UnsafeRawBufferPointer
  ) throws {
    let scalar = try requiredScalar(dictionary, field: field, style: style)
    do {
      let range = try validatedRange(scalar.range, bytes: bytes)
      guard allowsEmpty || !range.isEmpty else {
        throw VendorAppSessionSnapshotError.malformed
      }
    } catch {
      throw VendorAppSessionSnapshotError.requiredFieldWrongType(field.diagnostic)
    }
  }

  private static func requiredScalarEquals(
    _ dictionary: [String: VendorAppSessionLogNode],
    field: Field,
    expected: String,
    style: VendorAppSessionLogScalar.Style,
    bytes: UnsafeRawBufferPointer
  ) throws -> Bool {
    let scalar = try requiredScalar(dictionary, field: field, style: style)
    let range = try validatedRange(scalar.range, bytes: bytes)
    return equal(bytes, range: range, expected: expected)
  }

  private static func requireExactFields(
    _ dictionary: [String: VendorAppSessionLogNode],
    fields: [Field],
    expected: Set<String>
  ) throws {
    for field in fields where dictionary[field.key] == nil {
      throw VendorAppSessionSnapshotError.requiredFieldMissing(field.diagnostic)
    }
    guard Set(dictionary.keys) == expected else {
      throw VendorAppSessionSnapshotError.malformed
    }
  }

  private static func validatedRange(
    _ range: Range<Int>,
    bytes: UnsafeRawBufferPointer
  ) throws -> Range<Int> {
    guard range.lowerBound >= 0,
      range.upperBound <= bytes.count,
      range.count <= VendorCharonStartValidator.maximumTextBytes
    else { throw VendorAppSessionSnapshotError.malformed }
    return range
  }

  private static func decimalValue(
    _ range: Range<Int>,
    bytes: UnsafeRawBufferPointer
  ) throws -> Int32 {
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

  private static func equal(
    _ bytes: UnsafeRawBufferPointer,
    range: Range<Int>,
    expected: String
  ) -> Bool {
    let expectedBytes = Array(expected.utf8)
    guard range.count == expectedBytes.count else { return false }
    return expectedBytes.enumerated().allSatisfy { offset, byte in
      bytes[range.lowerBound + offset] == byte
    }
  }
}
