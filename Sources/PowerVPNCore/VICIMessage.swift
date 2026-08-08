import Foundation

/// One ordered element in a VICI message body.
public indirect enum VICIElement: Equatable, Sendable {
  case section(name: String, elements: [VICIElement])
  case keyValue(name: String, value: Data)
  case list(name: String, values: [Data])

  public static func keyValue(_ name: String, _ value: String) -> VICIElement {
    .keyValue(name: name, value: Data(value.utf8))
  }

  public static func list(_ name: String, _ values: [String]) -> VICIElement {
    .list(name: name, values: values.map { Data($0.utf8) })
  }

  var name: String {
    switch self {
    case .section(let name, _), .keyValue(let name, _), .list(let name, _):
      return name
    }
  }
}

/// An ordered VICI message body, without an operation or transport framing.
public struct VICIMessage: Equatable, Sendable {
  public let elements: [VICIElement]

  public init(elements: [VICIElement]) {
    self.elements = elements
  }
}

/// A VICI command request payload. The four-byte socket length prefix is not included.
public struct VICINamedRequest: Equatable, Sendable {
  public static let commandRequestOperation: UInt8 = 0

  public let command: String
  public let message: VICIMessage

  public init(command: String, message: VICIMessage) {
    self.command = command
    self.message = message
  }

  public func encodedPayload() throws -> Data {
    try VICIMessageCodec.encodeNamedRequest(self)
  }

  public static func decode(payload: Data) throws -> VICINamedRequest {
    try VICIMessageCodec.decodeNamedRequest(payload)
  }
}

public enum VICIMessageError: Error, Equatable, CustomStringConvertible, Sendable {
  case payloadTooLarge
  case invalidName
  case valueTooLarge
  case duplicateSiblingName
  case invalidOperation
  case malformedEncoding
  case unbalancedSection
  case invalidListEncoding

  public var description: String {
    switch self {
    case .payloadTooLarge:
      return "VICI payload exceeds the 512 KiB limit"
    case .invalidName:
      return "VICI names must be nonempty printable ASCII and at most 255 bytes"
    case .valueTooLarge:
      return "VICI values must be at most 65535 bytes"
    case .duplicateSiblingName:
      return "VICI sibling names must be unique"
    case .invalidOperation:
      return "VICI payload is not a named command request"
    case .malformedEncoding:
      return "VICI message encoding is malformed"
    case .unbalancedSection:
      return "VICI section nesting is unbalanced"
    case .invalidListEncoding:
      return "VICI list encoding is malformed"
    }
  }
}

public enum VICIMessageCodec {
  public static let maximumPayloadSize = 512 * 1_024

  static let sectionStart: UInt8 = 1
  static let sectionEnd: UInt8 = 2
  static let keyValue: UInt8 = 3
  static let listStart: UInt8 = 4
  static let listItem: UInt8 = 5
  static let listEnd: UInt8 = 6

  /// Encodes only the VICI message body (not an operation or socket framing).
  public static func encode(_ message: VICIMessage) throws -> Data {
    enum Action {
      case elements([VICIElement])
      case element(VICIElement)
      case endSection
    }

    var encoded = Data()
    var actions: [Action] = [.elements(message.elements)]

    while let action = actions.popLast() {
      switch action {
      case .elements(let elements):
        try validateUniqueSiblingNames(elements)
        for element in elements.reversed() {
          actions.append(.element(element))
        }
      case .element(let element):
        switch element {
        case .section(let name, let elements):
          try appendNamedType(sectionStart, name: name, to: &encoded)
          actions.append(.endSection)
          actions.append(.elements(elements))
        case .keyValue(let name, let value):
          try appendNamedType(keyValue, name: name, to: &encoded)
          try appendValue(value, to: &encoded)
        case .list(let name, let values):
          try appendNamedType(listStart, name: name, to: &encoded)
          for value in values {
            guard value.count <= UInt16.max else { throw VICIMessageError.valueTooLarge }
            encoded.append(listItem)
            try appendValue(value, to: &encoded)
          }
          encoded.append(listEnd)
        }
      case .endSection:
        encoded.append(sectionEnd)
      }
      try enforceMaximumSize(encoded.count)
    }
    return encoded
  }

  /// Encodes the payload consumed after VICI's four-byte socket length prefix.
  public static func encodeNamedRequest(_ request: VICINamedRequest) throws -> Data {
    let command = try encodedName(request.command)
    let body = try encode(request.message)
    var payload = Data([VICINamedRequest.commandRequestOperation, UInt8(command.count)])
    payload.append(command)
    payload.append(body)
    try enforceMaximumSize(payload.count)
    return payload
  }

  private static func validateUniqueSiblingNames(_ elements: [VICIElement]) throws {
    var names = Set<String>()
    for element in elements {
      _ = try encodedName(element.name)
      guard names.insert(element.name).inserted else {
        throw VICIMessageError.duplicateSiblingName
      }
    }
  }

  private static func appendNamedType(_ type: UInt8, name: String, to data: inout Data) throws {
    let bytes = try encodedName(name)
    data.append(type)
    data.append(UInt8(bytes.count))
    data.append(bytes)
  }

  private static func appendValue(_ value: Data, to data: inout Data) throws {
    guard value.count <= UInt16.max else { throw VICIMessageError.valueTooLarge }
    let length = UInt16(value.count)
    data.append(UInt8(length >> 8))
    data.append(UInt8(length & 0xff))
    data.append(value)
  }

  private static func encodedName(_ name: String) throws -> Data {
    let bytes = Data(name.utf8)
    guard !bytes.isEmpty, bytes.count <= UInt8.max,
      bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e })
    else {
      throw VICIMessageError.invalidName
    }
    return bytes
  }

  static func enforceMaximumSize(_ count: Int) throws {
    guard count <= maximumPayloadSize else { throw VICIMessageError.payloadTooLarge }
  }
}
