import Foundation

public enum VICIPacketOperation: UInt8, Codable, Sendable {
  case commandRequest = 0
  case commandResponse = 1
  case commandUnknown = 2
  case eventRegister = 3
  case eventUnregister = 4
  case eventConfirm = 5
  case eventUnknown = 6
  case event = 7
}

public enum VICIPacket: Equatable, Sendable {
  case commandResponse(VICIMessage)
  case commandUnknown
  case eventConfirm
  case eventUnknown
  case event(name: String, message: VICIMessage)

  public var operation: VICIPacketOperation {
    switch self {
    case .commandResponse: .commandResponse
    case .commandUnknown: .commandUnknown
    case .eventConfirm: .eventConfirm
    case .eventUnknown: .eventUnknown
    case .event: .event
    }
  }
}

public enum VICIPacketError: Error, Equatable, CustomStringConvertible, Sendable {
  case payloadTooLarge
  case emptyPayload
  case invalidOperation
  case invalidName
  case trailingData

  public var description: String {
    switch self {
    case .payloadTooLarge:
      return "VICI packet exceeds the 512 KiB limit"
    case .emptyPayload:
      return "VICI packet is empty"
    case .invalidOperation:
      return "VICI packet operation is not valid in a daemon response"
    case .invalidName:
      return "VICI packet name is malformed"
    case .trailingData:
      return "VICI packet contains unexpected trailing data"
    }
  }
}

public enum VICIPacketCodec {
  public static func encodeEventRegistration(_ event: String, register: Bool) throws -> Data {
    let name = try encodedName(event)
    let operation: VICIPacketOperation = register ? .eventRegister : .eventUnregister
    var payload = Data([operation.rawValue, UInt8(name.count)])
    payload.append(name)
    return payload
  }

  public static func decodeResponse(_ payload: Data) throws -> VICIPacket {
    guard payload.count <= VICIMessageCodec.maximumPayloadSize else {
      throw VICIPacketError.payloadTooLarge
    }
    guard let rawOperation = payload.first else { throw VICIPacketError.emptyPayload }
    guard let operation = VICIPacketOperation(rawValue: rawOperation) else {
      throw VICIPacketError.invalidOperation
    }

    switch operation {
    case .commandResponse:
      return .commandResponse(try VICIMessageCodec.decode(payload.dropFirstData()))
    case .commandUnknown:
      guard payload.count == 1 else { throw VICIPacketError.trailingData }
      return .commandUnknown
    case .eventConfirm:
      guard payload.count == 1 else { throw VICIPacketError.trailingData }
      return .eventConfirm
    case .eventUnknown:
      guard payload.count == 1 else { throw VICIPacketError.trailingData }
      return .eventUnknown
    case .event:
      guard payload.count >= 2 else { throw VICIPacketError.invalidName }
      let length = Int(payload[payload.startIndex + 1])
      guard length > 0, payload.count >= 2 + length else {
        throw VICIPacketError.invalidName
      }
      let nameData = payload.subdata(in: 2..<(2 + length))
      guard nameData.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }),
        let name = String(data: nameData, encoding: .ascii)
      else {
        throw VICIPacketError.invalidName
      }
      return .event(
        name: name,
        message: try VICIMessageCodec.decode(payload.subdata(in: (2 + length)..<payload.count))
      )
    case .commandRequest, .eventRegister, .eventUnregister:
      throw VICIPacketError.invalidOperation
    }
  }

  private static func encodedName(_ name: String) throws -> Data {
    let bytes = Data(name.utf8)
    guard !bytes.isEmpty, bytes.count <= UInt8.max,
      bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e })
    else {
      throw VICIPacketError.invalidName
    }
    return bytes
  }
}

extension Data {
  fileprivate func dropFirstData() -> Data {
    subdata(in: index(after: startIndex)..<endIndex)
  }
}
