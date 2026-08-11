import Foundation

indirect enum VendorAppSessionLogNode {
  case dictionary([String: VendorAppSessionLogNode])
  case array([VendorAppSessionLogNode])
  case scalar(VendorAppSessionLogScalar)
}

struct VendorAppSessionLogScalar {
  enum Style {
    case bare
    case quoted
  }

  let range: Range<Int>
  let style: Style
}

enum VendorAppSessionLogParserError: Error {
  case incomplete
  case invalidEncoding
  case syntax
}

struct VendorAppSessionLogParser {
  private let bytes: UnsafeRawBufferPointer
  private var index = 0
  private var nodeCount = 0
  private let maximumDepth = 5
  private let maximumCollectionCount = 64
  private let maximumNodeCount = 128
  private let maximumScalarBytes = 4_096

  init(bytes: UnsafeRawBufferPointer) {
    self.bytes = bytes
  }

  var consumedByteCount: Int {
    index
  }

  mutating func parsePrefix() throws -> (VendorAppSessionLogNode, Int) {
    let node = try parseValue(depth: 0)
    return (node, index)
  }

  mutating func parseComplete() throws -> VendorAppSessionLogNode {
    do {
      let node = try parseValue(depth: 0)
      skipWhitespace()
      guard index == bytes.count else {
        throw VendorAppSessionLogParserError.syntax
      }
      return node
    } catch is VendorAppSessionLogParserError {
      throw VendorAppSessionSnapshotError.malformed
    }
  }

  private mutating func parseValue(depth: Int) throws -> VendorAppSessionLogNode {
    guard depth <= maximumDepth else {
      throw VendorAppSessionLogParserError.syntax
    }
    nodeCount += 1
    guard nodeCount <= maximumNodeCount else {
      throw VendorAppSessionLogParserError.syntax
    }
    skipWhitespace()
    guard let byte = current else {
      throw VendorAppSessionLogParserError.incomplete
    }
    switch byte {
    case 0x7B:
      guard depth < maximumDepth else {
        throw VendorAppSessionLogParserError.syntax
      }
      return try parseDictionary(depth: depth + 1)
    case 0x28:
      guard depth < maximumDepth else {
        throw VendorAppSessionLogParserError.syntax
      }
      return try parseArray(depth: depth + 1)
    default:
      return try .scalar(parseScalar())
    }
  }

  private mutating func parseDictionary(depth: Int) throws -> VendorAppSessionLogNode {
    try expect(0x7B)
    var dictionary: [String: VendorAppSessionLogNode] = [:]
    while true {
      skipWhitespace()
      if consume(0x7D) { return .dictionary(dictionary) }
      guard dictionary.count < maximumCollectionCount else {
        throw VendorAppSessionLogParserError.syntax
      }
      let keyRange = try parseScalar()
      let key = try keyString(keyRange)
      guard dictionary[key] == nil else {
        throw VendorAppSessionLogParserError.syntax
      }
      skipWhitespace()
      try expect(0x3D)
      let value = try parseValue(depth: depth)
      skipWhitespace()
      try expect(0x3B)
      dictionary[key] = value
    }
  }

  private mutating func parseArray(depth: Int) throws -> VendorAppSessionLogNode {
    try expect(0x28)
    var values: [VendorAppSessionLogNode] = []
    while true {
      skipWhitespace()
      if consume(0x29) { return .array(values) }
      guard values.count < maximumCollectionCount else {
        throw VendorAppSessionLogParserError.syntax
      }
      values.append(try parseValue(depth: depth))
      skipWhitespace()
      if consume(0x2C) {
        skipWhitespace()
        guard current != 0x29 else {
          throw VendorAppSessionLogParserError.syntax
        }
        continue
      }
      try expect(0x29)
      return .array(values)
    }
  }

  private mutating func parseScalar() throws -> VendorAppSessionLogScalar {
    skipWhitespace()
    guard let first = current else {
      throw VendorAppSessionLogParserError.incomplete
    }
    if first == 0x22 {
      index += 1
      let start = index
      while let byte = current, byte != 0x22 {
        guard isCanonicalSourceByte(byte) else {
          throw VendorAppSessionLogParserError.invalidEncoding
        }
        guard byte != 0x5C, byte >= 0x20, index - start < maximumScalarBytes else {
          throw VendorAppSessionLogParserError.syntax
        }
        index += 1
      }
      guard current == 0x22 else {
        throw VendorAppSessionLogParserError.incomplete
      }
      let range = start..<index
      index += 1
      return VendorAppSessionLogScalar(range: range, style: .quoted)
    }
    let start = index
    if first == 0x2F, let next = byte(at: index + 1), next == 0x2F || next == 0x2A {
      throw VendorAppSessionLogParserError.syntax
    }
    while let byte = current,
      !isWhitespace(byte),
      ![0x3B, 0x2C, 0x29, 0x7D, 0x3D, 0x7B, 0x28].contains(byte)
    {
      guard isCanonicalSourceByte(byte) else {
        throw VendorAppSessionLogParserError.invalidEncoding
      }
      guard byte >= 0x21, byte != 0x22, byte != 0x5C,
        index - start < maximumScalarBytes
      else {
        throw VendorAppSessionLogParserError.syntax
      }
      if byte == 0x2F, let next = self.byte(at: index + 1),
        next == 0x2F || next == 0x2A
      {
        throw VendorAppSessionLogParserError.syntax
      }
      index += 1
    }
    guard index > start else {
      throw VendorAppSessionLogParserError.syntax
    }
    return VendorAppSessionLogScalar(range: start..<index, style: .bare)
  }

  private mutating func skipWhitespace() {
    while let byte = current, isWhitespace(byte) { index += 1 }
  }

  private func isWhitespace(_ byte: UInt8) -> Bool {
    byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
  }

  private func isCanonicalSourceByte(_ byte: UInt8) -> Bool {
    isWhitespace(byte) || (0x20...0x7E).contains(byte)
  }

  private var current: UInt8? {
    byte(at: index)
  }

  private func byte(at offset: Int) -> UInt8? {
    offset >= 0 && offset < bytes.count ? bytes[offset] : nil
  }

  private mutating func expect(_ byte: UInt8) throws {
    guard current != nil else {
      throw VendorAppSessionLogParserError.incomplete
    }
    guard consume(byte) else {
      throw VendorAppSessionLogParserError.syntax
    }
  }

  private mutating func consume(_ byte: UInt8) -> Bool {
    guard current == byte else { return false }
    index += 1
    return true
  }

  private func keyString(_ scalar: VendorAppSessionLogScalar) throws -> String {
    let range = scalar.range
    guard (1...64).contains(range.count),
      range.allSatisfy({ offset in
        let byte = bytes[offset]
        return (0x30...0x39).contains(byte)
          || (0x41...0x5A).contains(byte)
          || (0x61...0x7A).contains(byte)
          || byte == 0x2D || byte == 0x5F
      })
    else {
      throw VendorAppSessionLogParserError.syntax
    }
    return String(decoding: bytes[range], as: UTF8.self)
  }
}

extension VendorAppSessionLogNode {
  var dictionary: [String: VendorAppSessionLogNode]? {
    guard case .dictionary(let value) = self else { return nil }
    return value
  }

  var array: [VendorAppSessionLogNode]? {
    guard case .array(let value) = self else { return nil }
    return value
  }

  var scalarRange: Range<Int>? {
    scalar?.range
  }

  var scalar: VendorAppSessionLogScalar? {
    guard case .scalar(let value) = self else { return nil }
    return value
  }
}
