import Darwin

enum PortalPasswordBodyError: Error, Equatable, Sendable {
  case emptySerial
  case sizeOverflow
  case writeMismatch
}

enum PortalPasswordBodyBuilder {
  private static let base64Alphabet = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8
  )

  static func encode1(
    credentials: PortalCredentials,
    platformSerial: SecureBytes
  ) throws -> SecureBytes {
    let usernameCount = credentials.usernameByteCount
    let passwordCount = credentials.passwordByteCount
    let serialCount = platformSerial.count
    guard serialCount > 0 else { throw PortalPasswordBodyError.emptySerial }

    let usernameEncoded = try base64Count(usernameCount)
    let passwordEncoded = try base64Count(passwordCount)
    let fixedCount = "encode='1'&hardware_hash=&password=&terminal_type=mac&type=app&username=".utf8
      .count
    let total = try adding(
      try adding(fixedCount, serialCount),
      try adding(passwordEncoded, usernameEncoded)
    )

    return try SecureBytes.allocate(count: total) { output in
      var writer = ByteWriter(output)
      try writer.writeASCII("encode='1'&hardware_hash=")
      try platformSerial.withUnsafeBytes { try writer.write($0) }
      try writer.writeASCII("&password=")
      try credentials.withPasswordBytes { try writer.writeBase64($0) }
      try writer.writeASCII("&terminal_type=mac&type=app&username=")
      try credentials.withUsernameBytes { try writer.writeBase64($0) }
      guard writer.remaining == 0 else { throw PortalPasswordBodyError.writeMismatch }
    }
  }

  private static func base64Count(_ count: Int) throws -> Int {
    guard count >= 0, count <= (Int.max - 2) else {
      throw PortalPasswordBodyError.sizeOverflow
    }
    let groups = (count + 2) / 3
    guard groups <= Int.max / 4 else { throw PortalPasswordBodyError.sizeOverflow }
    return groups * 4
  }

  private static func adding(_ lhs: Int, _ rhs: Int) throws -> Int {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow else { throw PortalPasswordBodyError.sizeOverflow }
    return sum
  }

  private struct ByteWriter {
    private let buffer: UnsafeMutableRawBufferPointer
    private var offset = 0

    init(_ buffer: UnsafeMutableRawBufferPointer) {
      self.buffer = buffer
    }

    var remaining: Int { buffer.count - offset }

    mutating func writeASCII(_ value: StaticString) throws {
      guard value.utf8CodeUnitCount <= remaining else {
        throw PortalPasswordBodyError.writeMismatch
      }
      value.withUTF8Buffer { bytes in
        if !bytes.isEmpty {
          _ = memcpy(
            buffer.baseAddress!.advanced(by: offset),
            bytes.baseAddress!,
            bytes.count
          )
        }
        offset += bytes.count
      }
    }

    mutating func write(_ bytes: UnsafeRawBufferPointer) throws {
      guard bytes.count <= remaining else { throw PortalPasswordBodyError.writeMismatch }
      if !bytes.isEmpty {
        _ = memcpy(buffer.baseAddress!.advanced(by: offset), bytes.baseAddress!, bytes.count)
      }
      offset += bytes.count
    }

    mutating func writeBase64(_ input: UnsafeRawBufferPointer) throws {
      var index = 0
      while index + 3 <= input.count {
        let first = input[index]
        let second = input[index + 1]
        let third = input[index + 2]
        try writeBase64Byte(first >> 2)
        try writeBase64Byte(((first & 0x03) << 4) | (second >> 4))
        try writeBase64Byte(((second & 0x0f) << 2) | (third >> 6))
        try writeBase64Byte(third & 0x3f)
        index += 3
      }
      let tail = input.count - index
      if tail == 1 {
        let first = input[index]
        try writeBase64Byte(first >> 2)
        try writeBase64Byte((first & 0x03) << 4)
        try writeRawByte(0x3d)
        try writeRawByte(0x3d)
      } else if tail == 2 {
        let first = input[index]
        let second = input[index + 1]
        try writeBase64Byte(first >> 2)
        try writeBase64Byte(((first & 0x03) << 4) | (second >> 4))
        try writeBase64Byte((second & 0x0f) << 2)
        try writeRawByte(0x3d)
      }
    }

    private mutating func writeBase64Byte(_ index: UInt8) throws {
      try writeRawByte(PortalPasswordBodyBuilder.base64Alphabet[Int(index)])
    }

    private mutating func writeRawByte(_ value: UInt8) throws {
      guard remaining > 0 else { throw PortalPasswordBodyError.writeMismatch }
      buffer[offset] = value
      offset += 1
    }
  }
}
