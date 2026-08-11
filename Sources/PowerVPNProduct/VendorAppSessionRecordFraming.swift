struct VendorAppSessionLocatedRecord {
  let root: VendorAppSessionLogNode
  let dictionaryRange: Range<Int>
}

enum VendorAppSessionRecordFraming {
  private static let producer = Array("com.leadsec.charon-xpc[".utf8)
  private static let marker = Array("] charon xpc handle request:".utf8)
  private static let markerText = Array("charon xpc handle request:".utf8)
  private static let maximumRecordBytes = 16_384

  private enum RPC {
    case start
    case getVersion
    case updown
    case stop
    case logout
  }

  static func singleStartRecord(
    _ bytes: UnsafeRawBufferPointer
  ) throws -> VendorAppSessionLocatedRecord {
    var lineStart = 0
    var start: VendorAppSessionLocatedRecord?
    var requestCount = 0
    while lineStart < bytes.count {
      if let dictionaryStart = try dictionaryStart(at: lineStart, in: bytes) {
        requestCount += 1
        let suffix = UnsafeRawBufferPointer(rebasing: bytes[dictionaryStart..<bytes.count])
        var parser = VendorAppSessionLogParser(bytes: suffix)
        let parsed: (VendorAppSessionLogNode, Int)
        do {
          parsed = try parser.parsePrefix()
        } catch {
          throw VendorAppSessionSnapshotError.incomplete
        }
        guard (1...maximumRecordBytes).contains(parsed.1) else {
          throw VendorAppSessionSnapshotError.malformed
        }
        let end = dictionaryStart + parsed.1
        guard end + 1 < bytes.count, bytes[end] == 0x20, bytes[end + 1] == 0x0A else {
          throw VendorAppSessionSnapshotError.incomplete
        }
        switch try rpc(of: parsed.0, bytes: suffix) {
        case .start:
          guard start == nil else { throw VendorAppSessionSnapshotError.malformed }
          start = VendorAppSessionLocatedRecord(
            root: parsed.0,
            dictionaryRange: dictionaryStart..<end
          )
        case .getVersion, .updown, .stop:
          break
        case .logout:
          throw VendorAppSessionSnapshotError.stale
        }
        lineStart = end + 2
      } else {
        guard let lineEnd = newline(in: bytes, from: lineStart) else {
          throw VendorAppSessionSnapshotError.incomplete
        }
        if contains(markerText, in: bytes, range: lineStart..<lineEnd) {
          throw VendorAppSessionSnapshotError.malformed
        }
        lineStart = lineEnd + 1
      }
    }
    guard requestCount > 0, let start else {
      throw VendorAppSessionSnapshotError.resourceUnavailable
    }
    return start
  }

  private static func dictionaryStart(
    at lineStart: Int,
    in bytes: UnsafeRawBufferPointer
  ) throws -> Int? {
    guard validTimestamp(at: lineStart, in: bytes),
      matches(producer, at: lineStart + 24, in: bytes)
    else { return nil }
    var index = lineStart + 24 + producer.count
    guard consumeCanonicalDecimal(in: bytes, index: &index, maximumDigits: 10),
      index < bytes.count, bytes[index] == 0x3A
    else { return nil }
    index += 1
    guard consumeCanonicalDecimal(in: bytes, index: &index, maximumDigits: 20),
      matches(marker, at: index, in: bytes)
    else { return nil }
    index += marker.count
    guard index + 1 < bytes.count, bytes[index] == 0x7B, bytes[index + 1] == 0x0A else {
      throw VendorAppSessionSnapshotError.incomplete
    }
    return index
  }

  private static func validTimestamp(
    at start: Int,
    in bytes: UnsafeRawBufferPointer
  ) -> Bool {
    guard start >= 0, start + 24 <= bytes.count, bytes[start + 23] == 0x20 else {
      return false
    }
    let punctuation: [Int: UInt8] = [
      4: 0x2D, 7: 0x2D, 10: 0x20, 13: 0x3A, 16: 0x3A, 19: 0x2E,
    ]
    for offset in 0..<23 {
      if let expected = punctuation[offset] {
        guard bytes[start + offset] == expected else { return false }
      } else if !(0x30...0x39).contains(bytes[start + offset]) {
        return false
      }
    }
    guard let year = decimal(bytes, start, 4),
      let month = decimal(bytes, start + 5, 2),
      let day = decimal(bytes, start + 8, 2),
      let hour = decimal(bytes, start + 11, 2),
      let minute = decimal(bytes, start + 14, 2),
      let second = decimal(bytes, start + 17, 2)
    else { return false }
    return (1...12).contains(month) && (1...days(in: month, year: year)).contains(day)
      && (0...23).contains(hour) && (0...59).contains(minute)
      && (0...60).contains(second)
  }

  private static func consumeCanonicalDecimal(
    in bytes: UnsafeRawBufferPointer,
    index: inout Int,
    maximumDigits: Int
  ) -> Bool {
    let start = index
    while index < bytes.count, (0x30...0x39).contains(bytes[index]),
      index - start < maximumDigits
    {
      index += 1
    }
    let count = index - start
    return count > 0 && (count == 1 || bytes[start] != 0x30)
  }

  private static func rpc(
    of root: VendorAppSessionLogNode,
    bytes: UnsafeRawBufferPointer
  ) throws -> RPC {
    guard let dictionary = root.dictionary,
      let range = dictionary["rpc"]?.scalarRange,
      range.lowerBound >= 0,
      range.upperBound <= bytes.count
    else { throw VendorAppSessionSnapshotError.malformed }
    if equal(bytes, range, "start_connection") { return .start }
    if equal(bytes, range, "get_version") { return .getVersion }
    if equal(bytes, range, "updown_nc") { return .updown }
    if equal(bytes, range, "stop_connection") { return .stop }
    if equal(bytes, range, "logout") { return .logout }
    throw VendorAppSessionSnapshotError.malformed
  }

  private static func equal(
    _ bytes: UnsafeRawBufferPointer,
    _ range: Range<Int>,
    _ text: StaticString
  ) -> Bool {
    text.withUTF8Buffer { expected in
      range.count == expected.count
        && zip(range, expected).allSatisfy { bytes[$0.0] == $0.1 }
    }
  }

  private static func matches(
    _ expected: [UInt8],
    at start: Int,
    in bytes: UnsafeRawBufferPointer
  ) -> Bool {
    guard start >= 0, start + expected.count <= bytes.count else { return false }
    return expected.indices.allSatisfy { bytes[start + $0] == expected[$0] }
  }

  private static func contains(
    _ expected: [UInt8],
    in bytes: UnsafeRawBufferPointer,
    range: Range<Int>
  ) -> Bool {
    guard !expected.isEmpty, range.count >= expected.count else { return false }
    for index in range.lowerBound...(range.upperBound - expected.count) {
      if matches(expected, at: index, in: bytes) { return true }
    }
    return false
  }

  private static func newline(
    in bytes: UnsafeRawBufferPointer,
    from start: Int
  ) -> Int? {
    guard start >= 0, start < bytes.count else { return nil }
    return (start..<bytes.count).first { bytes[$0] == 0x0A }
  }

  private static func days(in month: Int, year: Int) -> Int {
    switch month {
    case 2:
      let leap =
        year.isMultiple(of: 400)
        || (year.isMultiple(of: 4) && !year.isMultiple(of: 100))
      return leap ? 29 : 28
    case 4, 6, 9, 11: return 30
    default: return 31
    }
  }

  private static func decimal(
    _ bytes: UnsafeRawBufferPointer,
    _ start: Int,
    _ count: Int
  ) -> Int? {
    var value = 0
    for index in start..<(start + count) {
      guard (0x30...0x39).contains(bytes[index]) else { return nil }
      value = value * 10 + Int(bytes[index] - 0x30)
    }
    return value
  }
}
