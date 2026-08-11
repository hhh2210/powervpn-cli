extension VendorAppSessionRecordFraming {
  static let producer = Array("com.leadsec.charon-xpc[".utf8)
  static let marker = Array("] charon xpc handle request:".utf8)
  static let markerText = Array("charon xpc handle request:".utf8)

  struct RecordHeader {
    let dictionaryStart: Int
    let producerIdentityRange: Range<Int>
  }

  enum MarkerCount {
    case zero
    case one
    case many
  }

  static func recordHeader(
    at lineStart: Int,
    in bytes: UnsafeRawBufferPointer
  ) throws -> RecordHeader? {
    guard validTimestamp(at: lineStart, in: bytes),
      matches(producer, at: lineStart + 24, in: bytes)
    else { return nil }
    var index = lineStart + 24 + producer.count
    let identityStart = index
    guard consumeCanonicalDecimal(in: bytes, index: &index, maximumDigits: 10),
      index < bytes.count, bytes[index] == 0x3A
    else { return nil }
    let identityEnd = index
    index += 1
    guard consumeCanonicalDecimal(in: bytes, index: &index, maximumDigits: 20) else {
      return nil
    }
    let identityRange = identityStart..<identityEnd
    guard matches(marker, at: index, in: bytes) else { return nil }
    index += marker.count
    guard index < bytes.count else {
      throw VendorAppSessionSnapshotError.incomplete
    }
    guard bytes[index] == 0x7B else {
      throw VendorAppSessionSnapshotError.recordRejected(.dictionaryRootShape)
    }
    guard index + 1 < bytes.count else {
      throw VendorAppSessionSnapshotError.incomplete
    }
    guard bytes[index + 1] == 0x0A else {
      throw VendorAppSessionSnapshotError.recordRejected(.dictionaryRootShape)
    }
    return RecordHeader(
      dictionaryStart: index,
      producerIdentityRange: identityRange
    )
  }

  static func markerCount(
    in bytes: UnsafeRawBufferPointer,
    range: Range<Int>
  ) -> MarkerCount {
    guard range.count >= markerText.count else { return .zero }
    var count = 0
    var index = range.lowerBound
    let lastStart = range.upperBound - markerText.count
    while index <= lastStart {
      if matches(markerText, at: index, in: bytes) {
        count += 1
        if count > 1 { return .many }
        index += markerText.count
      } else {
        index += 1
      }
    }
    return count == 1 ? .one : .zero
  }

  static func sameProducerIdentity(
    _ bytes: UnsafeRawBufferPointer,
    _ lhs: Range<Int>,
    _ rhs: Range<Int>
  ) -> Bool {
    lhs.count == rhs.count
      && zip(lhs, rhs).allSatisfy { bytes[$0.0] == bytes[$0.1] }
  }

  static func newline(
    in bytes: UnsafeRawBufferPointer,
    from start: Int
  ) -> Int? {
    guard start >= 0, start < bytes.count else { return nil }
    return (start..<bytes.count).first { bytes[$0] == 0x0A }
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

  private static func matches(
    _ expected: [UInt8],
    at start: Int,
    in bytes: UnsafeRawBufferPointer
  ) -> Bool {
    guard start >= 0, start + expected.count <= bytes.count else { return false }
    return expected.indices.allSatisfy { bytes[start + $0] == expected[$0] }
  }

  private static func days(in month: Int, year: Int) -> Int {
    switch month {
    case 2:
      let leap =
        year.isMultiple(of: 400)
        || (year.isMultiple(of: 4) && !year.isMultiple(of: 100))
      return leap ? 29 : 28
    case 4, 6, 9, 11:
      return 30
    default:
      return 31
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
