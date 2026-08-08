import Foundation
import Testing

@testable import PowerVPNCore

private typealias Correlation = ProtocolCorrelationDocument

private func metadataField(
  _ name: String,
  _ type: Correlation.FieldType,
  order: Int,
  length: Int? = nil,
  unit: Correlation.LengthUnit? = nil
) -> Correlation.Field {
  Correlation.Field(
    name: name,
    type: type,
    length: length,
    lengthUnit: unit,
    order: order,
    evidenceClass: .synthetic,
    confidence: .unknown
  )
}

private func transition(
  _ domain: Correlation.StateDomain,
  _ from: Correlation.State,
  _ to: Correlation.State,
  _ trigger: Correlation.Trigger,
  evidenceClass: Correlation.EvidenceClass = .synthetic
) -> Correlation.StateTransition {
  Correlation.StateTransition(
    domain: domain,
    from: from,
    to: to,
    trigger: trigger,
    evidenceClass: evidenceClass,
    confidence: .unknown
  )
}

private func validCorrelationDocument() -> Correlation {
  Correlation(
    source: .synthetic,
    events: [
      Correlation.Event(
        sequence: 1,
        relativeMilliseconds: 0,
        boundary: .controlPlane,
        transport: .https,
        direction: .clientToServer,
        kind: .request,
        operation: .sessionCheck,
        method: .get,
        pathTemplate: "/vpn/user/check/session",
        evidenceClass: .synthetic,
        confidence: .unknown,
        fields: [
          metadataField("key", .string, order: 1, length: 24, unit: .bytes)
        ],
        transitions: [transition(.authSession, .signedOut, .authenticating, .requestSent)]
      ),
      Correlation.Event(
        sequence: 2,
        relativeMilliseconds: 40,
        boundary: .controlPlane,
        transport: .https,
        direction: .serverToClient,
        kind: .response,
        operation: .sessionCheck,
        method: .get,
        pathTemplate: "/vpn/user/check/session",
        statusCode: 200,
        evidenceClass: .synthetic,
        confidence: .unknown,
        fields: [
          metadataField("sessionid", .string, order: 1, length: 24, unit: .bytes),
          metadataField("psk", .string, order: 2, length: 32, unit: .bytes),
          metadataField("vip", .string, order: 3, length: 10, unit: .bytes),
        ],
        transitions: [transition(.authSession, .authenticating, .valid, .responseSuccess)]
      ),
      Correlation.Event(
        sequence: 3,
        relativeMilliseconds: 60,
        boundary: .controlPlane,
        transport: .webSocket,
        direction: .clientToServer,
        kind: .open,
        operation: .webSocketOpen,
        pathTemplate: "/<UNKNOWN_PATH>",
        evidenceClass: .synthetic,
        confidence: .unknown,
        transitions: [transition(.controlChannel, .disconnected, .online, .socketOpened)]
      ),
      Correlation.Event(
        sequence: 4,
        relativeMilliseconds: 80,
        boundary: .controlPlane,
        transport: .webSocket,
        direction: .serverToClient,
        kind: .message,
        operation: .webSocketMessage,
        evidenceClass: .synthetic,
        confidence: .unknown,
        fields: [
          metadataField("resources", .array, order: 1, length: 2, unit: .elements),
          metadataField("resources[].name", .string, order: 2, length: 12, unit: .bytes),
        ],
        transitions: [transition(.resourceCatalog, .unavailable, .ready, .catalogReceived)]
      ),
      Correlation.Event(
        sequence: 5,
        relativeMilliseconds: 100,
        boundary: .xpc,
        transport: .xpc,
        direction: .guiToHelper,
        kind: .call,
        operation: .startConnection,
        helperFamily: .charon,
        evidenceClass: .synthetic,
        confidence: .unknown,
        fields: [
          metadataField("type", .string, order: 1),
          metadataField("rpc", .string, order: 2),
          metadataField("common", .dictionary, order: 3, length: 2, unit: .fields),
          metadataField("tunnels", .array, order: 4, length: 1, unit: .elements),
          metadataField("common.sessionid", .string, order: 5, length: 24, unit: .bytes),
          metadataField("common.psk", .string, order: 6, length: 32, unit: .bytes),
        ],
        transitions: [transition(.helperTunnel, .idle, .connecting, .helperCall)]
      ),
      Correlation.Event(
        sequence: 6,
        relativeMilliseconds: 120,
        boundary: .xpc,
        transport: .xpc,
        direction: .helperToGUI,
        kind: .reply,
        operation: .startConnection,
        helperFamily: .charon,
        resultClass: .success,
        evidenceClass: .synthetic,
        confidence: .unknown,
        transitions: [transition(.helperTunnel, .connecting, .established, .helperReply)]
      ),
    ])
}

private func encodedDocument() throws -> Data {
  try JSONEncoder().encode(validCorrelationDocument())
}

private func mutatedDocument(
  _ mutation: (inout [String: Any]) throws -> Void
) throws -> Data {
  var root = try #require(
    JSONSerialization.jsonObject(with: encodedDocument()) as? [String: Any]
  )
  try mutation(&root)
  return try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
}

@Test func valueFreeCorrelationRoundTripPreservesObservationOrder() throws {
  let document = validCorrelationDocument()
  let data = try JSONEncoder().encode(document)
  let decoded = try JSONDecoder().decode(Correlation.self, from: data)

  #expect(decoded == document)
  #expect(decoded.events.map(\.sequence) == [1, 2, 3, 4, 5, 6])
  #expect(decoded.events[1].fields.map(\.name) == ["sessionid", "psk", "vip"])
  #expect(ProtocolCorrelationRedactedValidator.validate(data: data).valid)
}

@Test func strictSchemaRejectsValueSlotsWithoutEchoingTheirContents() throws {
  let secret = "SECRET-SENTINEL-MUST-NOT-SURVIVE"
  let data = try mutatedDocument { root in
    var events = try #require(root["events"] as? [[String: Any]])
    var fields = try #require(events[0]["fields"] as? [[String: Any]])
    fields[0]["value"] = secret
    events[0]["fields"] = fields
    root["events"] = events
  }

  let report = ProtocolCorrelationRedactedValidator.validate(data: data)
  let output = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
  #expect(!report.valid)
  #expect(report.issues.map(\.code) == ["invalid_schema"])
  #expect(!output.contains(secret))
}

@Test func strictSchemaRejectsRawTransportSlots() throws {
  for forbidden in ["body", "headers", "rawDescription", "cookieValue", "auditToken"] {
    let data = try mutatedDocument { root in
      var events = try #require(root["events"] as? [[String: Any]])
      events[0][forbidden] = "SECRET-SENTINEL"
      root["events"] = events
    }
    #expect(!ProtocolCorrelationRedactedValidator.validate(data: data).valid)
  }
}

@Test func sensitiveFieldNamesRemainMetadataOnly() throws {
  let data = try encodedDocument()
  let encoded = String(decoding: data, as: UTF8.self)
  #expect(encoded.contains("\"psk\""))
  #expect(!encoded.contains("\"value\":"))
  #expect(!encoded.contains("\"body\":"))
  #expect(ProtocolCorrelationRedactedValidator.validate(data: data).valid)
}

@Test func rejectsUnsafeFlagsAndOversizedInput() {
  let unsafe = Correlation(
    source: .synthetic,
    containsSecrets: true,
    containsReplayableCapture: true,
    events: validCorrelationDocument().events
  )
  let report = ProtocolCorrelationRedactedValidator.validate(unsafe)
  #expect(report.issues.map(\.path).contains("containsSecrets"))
  #expect(report.issues.map(\.path).contains("containsReplayableCapture"))

  let oversized = Data(repeating: 0x20, count: 1_048_577)
  #expect(
    ProtocolCorrelationRedactedValidator.validate(data: oversized).issues.first?.code
      == "size_limit")
}

@Test func rejectsEventAndFieldOrderDrift() throws {
  let data = try mutatedDocument { root in
    var events = try #require(root["events"] as? [[String: Any]])
    events[1]["sequence"] = 9
    var fields = try #require(events[1]["fields"] as? [[String: Any]])
    fields[1]["order"] = 7
    events[1]["fields"] = fields
    root["events"] = events
  }
  let report = ProtocolCorrelationRedactedValidator.validate(data: data)
  #expect(report.issues.map(\.code).filter { $0 == "invalid_order" }.count == 2)
}

@Test func rejectsDirectionPathAndLengthUnitMismatches() throws {
  let data = try mutatedDocument { root in
    var events = try #require(root["events"] as? [[String: Any]])
    events[0]["direction"] = "server_to_client"
    events[0]["pathTemplate"] = "/vpn/user/check/session?token=SECRET-SENTINEL"
    var fields = try #require(events[0]["fields"] as? [[String: Any]])
    fields[0]["lengthUnit"] = "elements"
    events[0]["fields"] = fields
    root["events"] = events
  }
  let report = ProtocolCorrelationRedactedValidator.validate(data: data)
  let output = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
  #expect(!report.valid)
  #expect(report.issues.contains { $0.code == "invalid_combination" })
  #expect(!output.contains("SECRET-SENTINEL"))
}

@Test func rejectsStateDiscontinuityAndWrongDomainState() throws {
  let data = try mutatedDocument { root in
    var events = try #require(root["events"] as? [[String: Any]])
    var transitions = try #require(events[1]["transitions"] as? [[String: Any]])
    transitions[0]["from"] = "expired"
    transitions[0]["to"] = "ready"
    events[1]["transitions"] = transitions
    root["events"] = events
  }
  let report = ProtocolCorrelationRedactedValidator.validate(data: data)
  #expect(report.issues.contains { $0.code == "state_discontinuity" })
  #expect(report.issues.contains { $0.code == "invalid_combination" })
}

@Test func unknownFactsStayExplicitWithoutGuessing() {
  let event = Correlation.Event(
    sequence: 1,
    boundary: .xpc,
    transport: .xpc,
    direction: .guiToHelper,
    kind: .call,
    operation: .unknown,
    evidenceClass: .staticBinary,
    confidence: .unknown,
    transitions: [
      transition(
        .helperTunnel,
        .unknown,
        .unknown,
        .unknown,
        evidenceClass: .staticBinary
      )
    ]
  )
  let report = ProtocolCorrelationRedactedValidator.validate(
    Correlation(source: .staticBinary, events: [event])
  )
  #expect(report.valid)
}
