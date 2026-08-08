import Foundation

enum ClosedJSONShape {
  static func hasUniqueObjectKeys(in data: Data) -> Bool {
    do {
      var scanner = JSONStructureScanner(data: data)
      try scanner.scanDocument()
      return true
    } catch {
      return false
    }
  }

  static func hasExactObject(_ value: Any?, keys: Set<String>) -> Bool {
    guard let object = value as? [String: Any] else { return false }
    return Set(object.keys) == keys
  }

  static func hasOptionalExactObject(
    _ root: [String: Any],
    key: String,
    keys: Set<String>
  ) -> Bool {
    guard let value = root[key] else { return true }
    return hasExactObject(value, keys: keys)
  }

  static func hasOnlyAllowedKeys(
    _ object: [String: Any],
    required: Set<String>,
    optional: Set<String>
  ) -> Bool {
    let keys = Set(object.keys)
    return required.isSubset(of: keys) && keys.isSubset(of: required.union(optional))
  }
}

private struct JSONStructureScanner {
  private static let maximumDepth = 128

  private let bytes: [UInt8]
  private var offset = 0

  init(data: Data) {
    bytes = Array(data)
  }

  mutating func scanDocument() throws {
    skipWhitespace()
    try scanValue(depth: 0)
    skipWhitespace()
    guard offset == bytes.count else { throw JSONStructureScanError.invalidJSON }
  }

  private mutating func scanValue(depth: Int) throws {
    guard depth <= Self.maximumDepth, let byte = peek() else {
      throw JSONStructureScanError.invalidJSON
    }
    switch byte {
    case 0x7B:
      try scanObject(depth: depth)
    case 0x5B:
      try scanArray(depth: depth)
    case 0x22:
      _ = try scanStringRange()
    case 0x74:
      try consumeLiteral([0x74, 0x72, 0x75, 0x65])
    case 0x66:
      try consumeLiteral([0x66, 0x61, 0x6C, 0x73, 0x65])
    case 0x6E:
      try consumeLiteral([0x6E, 0x75, 0x6C, 0x6C])
    case 0x2D, 0x30...0x39:
      try scanNumber()
    default:
      throw JSONStructureScanError.invalidJSON
    }
  }

  private mutating func scanObject(depth: Int) throws {
    try consume(0x7B)
    skipWhitespace()
    if consumeIfPresent(0x7D) { return }

    var keys = Set<String>()
    while true {
      let range = try scanStringRange()
      let key = try JSONDecoder().decode(String.self, from: Data(bytes[range]))
      guard keys.insert(key).inserted else {
        throw JSONStructureScanError.duplicateObjectKey
      }
      skipWhitespace()
      try consume(0x3A)
      skipWhitespace()
      try scanValue(depth: depth + 1)
      skipWhitespace()
      if consumeIfPresent(0x7D) { return }
      try consume(0x2C)
      skipWhitespace()
    }
  }

  private mutating func scanArray(depth: Int) throws {
    try consume(0x5B)
    skipWhitespace()
    if consumeIfPresent(0x5D) { return }

    while true {
      try scanValue(depth: depth + 1)
      skipWhitespace()
      if consumeIfPresent(0x5D) { return }
      try consume(0x2C)
      skipWhitespace()
    }
  }

  private mutating func scanStringRange() throws -> Range<Int> {
    let start = offset
    try consume(0x22)
    while let byte = peek() {
      offset += 1
      switch byte {
      case 0x22:
        return start..<offset
      case 0x5C:
        guard let escaped = peek() else { throw JSONStructureScanError.invalidJSON }
        offset += 1
        if escaped == 0x75 {
          for _ in 0..<4 {
            guard let hex = peek(), isHexDigit(hex) else {
              throw JSONStructureScanError.invalidJSON
            }
            offset += 1
          }
        } else if ![0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74].contains(escaped) {
          throw JSONStructureScanError.invalidJSON
        }
      case 0x00...0x1F:
        throw JSONStructureScanError.invalidJSON
      default:
        continue
      }
    }
    throw JSONStructureScanError.invalidJSON
  }

  private mutating func scanNumber() throws {
    _ = consumeIfPresent(0x2D)
    if consumeIfPresent(0x30) {
      guard !isDigit(peek()) else { throw JSONStructureScanError.invalidJSON }
    } else {
      guard let first = peek(), (0x31...0x39).contains(first) else {
        throw JSONStructureScanError.invalidJSON
      }
      offset += 1
      consumeDigits()
    }
    if consumeIfPresent(0x2E) {
      guard isDigit(peek()) else { throw JSONStructureScanError.invalidJSON }
      consumeDigits()
    }
    if consumeIfPresent(0x65) || consumeIfPresent(0x45) {
      _ = consumeIfPresent(0x2B) || consumeIfPresent(0x2D)
      guard isDigit(peek()) else { throw JSONStructureScanError.invalidJSON }
      consumeDigits()
    }
  }

  private mutating func consumeDigits() {
    while isDigit(peek()) {
      offset += 1
    }
  }

  private mutating func consumeLiteral(_ literal: [UInt8]) throws {
    guard offset <= bytes.count, literal.count <= bytes.count - offset,
      Array(bytes[offset..<(offset + literal.count)]) == literal
    else {
      throw JSONStructureScanError.invalidJSON
    }
    offset += literal.count
  }

  private mutating func consume(_ byte: UInt8) throws {
    guard consumeIfPresent(byte) else { throw JSONStructureScanError.invalidJSON }
  }

  private mutating func consumeIfPresent(_ byte: UInt8) -> Bool {
    guard peek() == byte else { return false }
    offset += 1
    return true
  }

  private mutating func skipWhitespace() {
    while let byte = peek(), [0x20, 0x09, 0x0A, 0x0D].contains(byte) {
      offset += 1
    }
  }

  private func peek() -> UInt8? {
    offset < bytes.count ? bytes[offset] : nil
  }

  private func isDigit(_ byte: UInt8?) -> Bool {
    guard let byte else { return false }
    return (0x30...0x39).contains(byte)
  }

  private func isHexDigit(_ byte: UInt8) -> Bool {
    (0x30...0x39).contains(byte) || (0x41...0x46).contains(byte)
      || (0x61...0x66).contains(byte)
  }
}

private enum JSONStructureScanError: Error {
  case duplicateObjectKey
  case invalidJSON
}
