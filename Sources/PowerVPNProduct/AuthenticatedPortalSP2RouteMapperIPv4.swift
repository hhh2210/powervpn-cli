import Darwin
import PowerVPNCore

enum PortalSP2IPv4 {
  /// Parses dotted decimal into the same big-endian numeric value that the
  /// vendor obtains by `inet_pton` followed by `ntohl` on x86_64.
  static func parse(
    _ bytes: UnsafeRawBufferPointer,
    range: Range<Int>
  ) -> UInt32? {
    guard !range.isEmpty else { return nil }
    var address: UInt32 = 0
    var octetStart = range.lowerBound
    var octets = 0
    for index in range.lowerBound...range.upperBound {
      if index == range.upperBound || bytes[index] == 0x2e {
        let part = octetStart..<index
        guard !part.isEmpty, part.count <= 3,
          !(part.count > 1 && bytes[part.lowerBound] == 0x30),
          let value = decimal(bytes, range: part), value <= 255
        else { return nil }
        address = (address << 8) | UInt32(value)
        octets += 1
        octetStart = index + 1
      }
    }
    return octets == 4 ? address : nil
  }

  static func decimal(
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

enum PortalSP2IPv4RangeMapper {
  static func routes(
    _ scalar: PortalSP2Scalar,
    lineage: VendorCharonStartLineage
  ) throws -> [VendorCharonStartRouteCandidate]? {
    try scalar.withBytes { bytes in
      guard !bytes.isEmpty, !bytes.contains(0), !bytes.contains(0x2f) else {
        return nil
      }
      let separators = bytes.indices.filter { bytes[$0] == 0x2d }
      guard separators.count == 1, let separator = separators.first,
        let low = PortalSP2IPv4.parse(bytes, range: 0..<separator),
        let high = PortalSP2IPv4.parse(bytes, range: (separator + 1)..<bytes.count),
        low <= high
      else { return nil }

      return minimalCover(low: low, high: high).map { block in
        VendorCharonStartRouteCandidate(
          network: VendorCharonStartTextValue(
            value: PortalSP2IPv4TextMaterial(block.network),
            source: .authenticatedPortalResource,
            lineage: lineage
          ),
          prefix: VendorCharonStartPrefixValue(
            value: .integer(block.prefix),
            source: .authenticatedPortalResource,
            lineage: lineage
          )
        )
      }
    }
  }

  /// Greedily chooses the largest aligned power-of-two block that fits the
  /// remaining inclusive range. This is the vendor algorithm's intended
  /// host-order behavior, expressed with UInt64 to make the /0 wrap explicit.
  private static func minimalCover(
    low: UInt32,
    high: UInt32
  ) -> [(network: UInt32, prefix: Int32)] {
    var cursor = UInt64(low)
    let upper = UInt64(high)
    var result: [(network: UInt32, prefix: Int32)] = []
    while cursor <= upper {
      var blockSize = cursor == 0 ? UInt64(1) << 32 : cursor & (~cursor &+ 1)
      let remaining = upper - cursor + 1
      while blockSize > remaining { blockSize >>= 1 }
      let prefix = Int32(32 - blockSize.trailingZeroBitCount)
      result.append((UInt32(cursor), prefix))
      cursor += blockSize
    }
    return result
  }
}

/// Formats a derived host-order IPv4 value only inside the Core borrow. No
/// computed route string is retained in Product state or serialized to JSON.
struct PortalSP2IPv4TextMaterial: VendorCharonStartTextMaterial {
  private let address: UInt32
  let byteCount: Int

  init(_ address: UInt32) {
    self.address = address
    byteCount = (0..<4).reduce(3) {
      $0 + Self.digitCount(Self.octet(address, at: $1))
    }
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 15) { storage in
      defer {
        if let baseAddress = storage.baseAddress {
          _ = memset_s(baseAddress, storage.count, 0, storage.count)
        }
      }
      var offset = 0
      for index in 0..<4 {
        if index > 0 {
          storage[offset] = 0x2e
          offset += 1
        }
        let octet = Self.octet(address, at: index)
        offset += Self.writeDecimal(octet, to: storage, at: offset)
      }
      return try body(UnsafeRawBufferPointer(start: storage.baseAddress, count: offset))
    }
  }

  private static func octet(_ address: UInt32, at index: Int) -> UInt8 {
    UInt8((address >> UInt32(24 - index * 8)) & 0xff)
  }

  private static func digitCount(_ value: UInt8) -> Int {
    value >= 100 ? 3 : (value >= 10 ? 2 : 1)
  }

  private static func writeDecimal(
    _ value: UInt8,
    to storage: UnsafeMutableBufferPointer<UInt8>,
    at offset: Int
  ) -> Int {
    let integer = Int(value)
    if integer >= 100 {
      storage[offset] = UInt8(integer / 100) + 0x30
      storage[offset + 1] = UInt8((integer / 10) % 10) + 0x30
      storage[offset + 2] = UInt8(integer % 10) + 0x30
      return 3
    }
    if integer >= 10 {
      storage[offset] = UInt8(integer / 10) + 0x30
      storage[offset + 1] = UInt8(integer % 10) + 0x30
      return 2
    }
    storage[offset] = value + 0x30
    return 1
  }
}
