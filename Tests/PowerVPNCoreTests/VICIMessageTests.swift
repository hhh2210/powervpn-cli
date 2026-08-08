import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VICIMessageTests {
  @Test func encodesActualNamedRequestPayloadWithoutTransportLength() throws {
    let message = VICIMessage(elements: [
      .section(
        name: "a",
        elements: [
          .keyValue("b", "c"),
          .list(name: "d", values: [Data("e".utf8), Data()]),
        ]
      )
    ])
    let request = VICINamedRequest(command: "load-conn", message: message)

    let payload = try request.encodedPayload()
    let expected = Data([
      0x00, 0x09, 0x6c, 0x6f, 0x61, 0x64, 0x2d, 0x63, 0x6f, 0x6e, 0x6e,
      0x01, 0x01, 0x61,
      0x03, 0x01, 0x62, 0x00, 0x01, 0x63,
      0x04, 0x01, 0x64, 0x05, 0x00, 0x01, 0x65, 0x05, 0x00, 0x00, 0x06,
      0x02,
    ])

    #expect(payload == expected)
    #expect(try VICINamedRequest.decode(payload: payload) == request)
  }

  @Test func preservesElementAndListOrderAcrossRoundTrip() throws {
    let message = VICIMessage(elements: [
      .keyValue("first", "1"),
      .section(
        name: "nested",
        elements: [
          .list("ordered", ["a", "b", "c"]),
          .keyValue("last", "2"),
        ]
      ),
      .list("tail", ["x"]),
    ])

    #expect(try VICIMessageCodec.decode(VICIMessageCodec.encode(message)) == message)
  }

  @Test func enforcesNameAndValueBounds() throws {
    let maximumName = String(repeating: "a", count: 255)
    let maximumValue = Data(repeating: 0xa5, count: Int(UInt16.max))
    let valid = VICIMessage(elements: [.keyValue(name: maximumName, value: maximumValue)])
    #expect(try VICIMessageCodec.decode(VICIMessageCodec.encode(valid)) == valid)

    try expectVICIError(.invalidName) {
      try VICIMessageCodec.encode(VICIMessage(elements: [.list(name: "", values: [])]))
    }
    try expectVICIError(.invalidName) {
      try VICIMessageCodec.encode(
        VICIMessage(elements: [.list(name: String(repeating: "a", count: 256), values: [])])
      )
    }
    try expectVICIError(.invalidName) {
      try VICIMessageCodec.encode(VICIMessage(elements: [.list(name: "né", values: [])]))
    }
    try expectVICIError(.valueTooLarge) {
      try VICIMessageCodec.encode(
        VICIMessage(elements: [.keyValue(name: "key", value: Data(count: 65_536))])
      )
    }
  }

  @Test func rejectsDuplicateNamesWithinEachSiblingScope() throws {
    let duplicate = VICIMessage(elements: [
      .keyValue("same", "value"),
      .section(name: "same", elements: []),
    ])
    try expectVICIError(.duplicateSiblingName) {
      try VICIMessageCodec.encode(duplicate)
    }

    let encodedDuplicate = Data([
      0x03, 0x01, 0x61, 0x00, 0x01, 0x76,
      0x04, 0x01, 0x61, 0x06,
    ])
    try expectVICIError(.duplicateSiblingName) {
      try VICIMessageCodec.decode(encodedDuplicate)
    }
  }

  @Test func rejectsMalformedElementNestingAndNamedRequestOperation() throws {
    try expectVICIError(.unbalancedSection) {
      try VICIMessageCodec.decode(Data([0x01, 0x01, 0x61]))
    }
    try expectVICIError(.invalidListEncoding) {
      try VICIMessageCodec.decode(Data([0x04, 0x01, 0x61, 0x03]))
    }
    try expectVICIError(.malformedEncoding) {
      try VICIMessageCodec.decode(Data([0x07]))
    }
    try expectVICIError(.invalidOperation) {
      try VICIMessageCodec.decodeNamedRequest(Data([0x01, 0x01, 0x61]))
    }
  }

  @Test func appliesDaemonSizeCapToTheWholeNamedPayload() throws {
    let values = (0..<8).map { index in
      VICIElement.keyValue(
        name: "k\(index)",
        value: Data(repeating: UInt8(index), count: Int(UInt16.max))
      )
    }
    try expectVICIError(.payloadTooLarge) {
      try VICINamedRequest(
        command: "load-conn",
        message: VICIMessage(elements: values)
      ).encodedPayload()
    }
    try expectVICIError(.payloadTooLarge) {
      try VICIMessageCodec.decodeNamedRequest(
        Data(count: VICIMessageCodec.maximumPayloadSize + 1)
      )
    }
  }
}

private func expectVICIError<T>(
  _ expected: VICIMessageError,
  _ operation: () throws -> T
) throws {
  do {
    _ = try operation()
    #expect(Bool(false), "expected VICI error")
  } catch let error as VICIMessageError {
    #expect(error == expected)
  }
}
