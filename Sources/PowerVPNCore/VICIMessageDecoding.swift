import Foundation

extension VICIMessageCodec {
  private struct DecodeFrame {
    let name: String?
    var elements: [VICIElement]
    var siblingNames: Set<String>
  }

  /// Decodes only a VICI message body (not an operation or socket framing).
  public static func decode(_ data: Data) throws -> VICIMessage {
    try enforceMaximumSize(data.count)

    var cursor = Cursor(data)
    var frames = [DecodeFrame(name: nil, elements: [], siblingNames: [])]

    while !cursor.isAtEnd {
      let type = try cursor.readByte()
      switch type {
      case sectionStart:
        let name = try cursor.readName()
        try register(name, in: &frames[frames.count - 1])
        frames.append(DecodeFrame(name: name, elements: [], siblingNames: []))
      case sectionEnd:
        guard frames.count > 1 else { throw VICIMessageError.unbalancedSection }
        let completed = frames.removeLast()
        frames[frames.count - 1].elements.append(
          .section(name: completed.name!, elements: completed.elements)
        )
      case keyValue:
        let name = try cursor.readName()
        try register(name, in: &frames[frames.count - 1])
        let value = try cursor.readValue()
        frames[frames.count - 1].elements.append(.keyValue(name: name, value: value))
      case listStart:
        let name = try cursor.readName()
        try register(name, in: &frames[frames.count - 1])
        frames[frames.count - 1].elements.append(
          .list(name: name, values: try cursor.readList())
        )
      case listItem, listEnd:
        throw VICIMessageError.invalidListEncoding
      default:
        throw VICIMessageError.malformedEncoding
      }
    }

    guard frames.count == 1 else { throw VICIMessageError.unbalancedSection }
    return VICIMessage(elements: frames[0].elements)
  }

  /// Decodes the payload consumed after VICI's four-byte socket length prefix.
  public static func decodeNamedRequest(_ payload: Data) throws -> VICINamedRequest {
    try enforceMaximumSize(payload.count)
    var cursor = Cursor(payload)
    guard try cursor.readByte() == VICINamedRequest.commandRequestOperation else {
      throw VICIMessageError.invalidOperation
    }
    let command = try cursor.readName()
    return VICINamedRequest(
      command: command,
      message: try decode(cursor.remainingData())
    )
  }

  private static func register(_ name: String, in frame: inout DecodeFrame) throws {
    guard frame.siblingNames.insert(name).inserted else {
      throw VICIMessageError.duplicateSiblingName
    }
  }

  private struct Cursor {
    let data: Data
    var offset = 0

    init(_ data: Data) {
      self.data = data
    }

    var isAtEnd: Bool { offset == data.count }

    mutating func readByte() throws -> UInt8 {
      guard offset < data.count else { throw VICIMessageError.malformedEncoding }
      defer { offset += 1 }
      return data[offset]
    }

    mutating func readName() throws -> String {
      let length = Int(try readByte())
      guard length > 0 else { throw VICIMessageError.invalidName }
      let bytes = try read(count: length)
      guard bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }),
        let name = String(data: bytes, encoding: .ascii)
      else {
        throw VICIMessageError.invalidName
      }
      return name
    }

    mutating func readValue() throws -> Data {
      let high = UInt16(try readByte())
      let low = UInt16(try readByte())
      return try read(count: Int((high << 8) | low))
    }

    mutating func readList() throws -> [Data] {
      var values: [Data] = []
      while !isAtEnd {
        let type = try readByte()
        if type == VICIMessageCodec.listEnd {
          return values
        }
        guard type == VICIMessageCodec.listItem else {
          throw VICIMessageError.invalidListEncoding
        }
        values.append(try readValue())
      }
      throw VICIMessageError.invalidListEncoding
    }

    mutating func read(count: Int) throws -> Data {
      guard count >= 0, offset <= data.count, count <= data.count - offset else {
        throw VICIMessageError.malformedEncoding
      }
      defer { offset += count }
      return data.subdata(in: offset..<(offset + count))
    }

    func remainingData() -> Data {
      data.subdata(in: offset..<data.count)
    }
  }
}
