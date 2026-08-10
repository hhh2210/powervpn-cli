import Darwin

func portalBytesMatch(
  _ bytes: UnsafeRawBufferPointer,
  _ needle: [UInt8],
  at index: Int
) -> Bool {
  guard index >= 0, index + needle.count <= bytes.count else { return false }
  for offset in needle.indices where bytes[index + offset] != needle[offset] {
    return false
  }
  return true
}

struct PortalCookieByteWriter {
  private let output: UnsafeMutableRawBufferPointer
  private var offset = 0

  init(_ output: UnsafeMutableRawBufferPointer) {
    self.output = output
  }

  var remaining: Int { output.count - offset }

  mutating func write(_ bytes: UnsafeRawBufferPointer) throws {
    guard bytes.count <= remaining else { throw LeadSecPortalCookieJarError.writeMismatch }
    if !bytes.isEmpty {
      _ = memcpy(output.baseAddress!.advanced(by: offset), bytes.baseAddress!, bytes.count)
    }
    offset += bytes.count
  }

  mutating func write(_ bytes: [UInt8]) throws {
    try bytes.withUnsafeBytes { try write($0) }
  }

  mutating func writeReplacing(
    _ bytes: UnsafeRawBufferPointer,
    source: [UInt8],
    replacement: [UInt8]
  ) throws {
    var index = 0
    while index < bytes.count {
      if portalBytesMatch(bytes, source, at: index) {
        try write(replacement)
        index += source.count
      } else {
        guard remaining > 0 else { throw LeadSecPortalCookieJarError.writeMismatch }
        output[offset] = bytes[index]
        offset += 1
        index += 1
      }
    }
  }
}
