import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VICIPacketTests {
  @Test func encodesEventRegistrationExactly() throws {
    #expect(
      try VICIPacketCodec.encodeEventRegistration("list-conn", register: true)
        == Data([0x03, 0x09]) + Data("list-conn".utf8)
    )
    #expect(
      try VICIPacketCodec.encodeEventRegistration("list-conn", register: false)
        == Data([0x04, 0x09]) + Data("list-conn".utf8)
    )
  }

  @Test func decodesCommandResponseAndEvent() throws {
    let message = VICIMessage(elements: [.keyValue("success", "yes")])
    let body = try VICIMessageCodec.encode(message)

    #expect(
      try VICIPacketCodec.decodeResponse(
        Data([VICIPacketOperation.commandResponse.rawValue]) + body)
        == .commandResponse(message)
    )
    let event =
      Data([VICIPacketOperation.event.rawValue, 0x09]) + Data("list-conn".utf8) + body
    #expect(
      try VICIPacketCodec.decodeResponse(event)
        == .event(name: "list-conn", message: message)
    )
  }

  @Test func rejectsClientOperationsAndMalformedNames() throws {
    try expectPacketError(.invalidOperation) {
      try VICIPacketCodec.decodeResponse(Data([0x00, 0x01, 0x61]))
    }
    try expectPacketError(.invalidName) {
      try VICIPacketCodec.decodeResponse(Data([0x07, 0x02, 0x61]))
    }
    try expectPacketError(.trailingData) {
      try VICIPacketCodec.decodeResponse(Data([0x02, 0x00]))
    }
    try expectPacketError(.invalidOperation) {
      try VICIPacketCodec.decodeResponse(Data([0xff]))
    }
  }
}

private func expectPacketError<T>(
  _ expected: VICIPacketError,
  _ operation: () throws -> T
) throws {
  do {
    _ = try operation()
    Issue.record("expected VICI packet error")
  } catch let error as VICIPacketError {
    #expect(error == expected)
  }
}
