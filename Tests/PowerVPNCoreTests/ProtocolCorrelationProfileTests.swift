import Foundation
import Testing

@testable import PowerVPNCore

private typealias Correlation = ProtocolCorrelationDocument

private func profileField(
  _ name: String,
  _ type: Correlation.FieldType,
  order: Int,
  confidence: Correlation.Confidence = .unknown
) -> Correlation.Field {
  Correlation.Field(
    name: name,
    type: type,
    order: order,
    evidenceClass: .synthetic,
    confidence: confidence
  )
}

private func syntheticReport(_ event: Correlation.Event) -> ProtocolCorrelationValidationReport {
  ProtocolCorrelationRedactedValidator.validate(
    Correlation(source: .synthetic, events: [event])
  )
}

private func sessionEvent(fields: [Correlation.Field]) -> Correlation.Event {
  Correlation.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .clientToServer,
    kind: .request,
    operation: .sessionCheck,
    method: .get,
    pathTemplate: "/vpn/user/check/session",
    evidenceClass: .synthetic,
    confidence: .unknown,
    fields: fields
  )
}

private func toggleEvent(fields: [Correlation.Field]) -> Correlation.Event {
  Correlation.Event(
    sequence: 1,
    boundary: .xpc,
    transport: .xpc,
    direction: .guiToHelper,
    kind: .call,
    operation: .resourceToggleNC,
    helperFamily: .charon,
    evidenceClass: .synthetic,
    confidence: .unknown,
    fields: fields
  )
}

@Test func rejectsMissingExtraWrongNameTypeAndOrderForSessionCheck() {
  let invalidProfiles: [[Correlation.Field]] = [
    [],
    [
      profileField("key", .string, order: 1),
      profileField("hostid", .string, order: 2),
    ],
    [profileField("key", .number, order: 1)],
    [profileField("username", .string, order: 1)],
    [profileField("key", .string, order: 2)],
  ]
  for fields in invalidProfiles {
    let report = syntheticReport(sessionEvent(fields: fields))
    #expect(!report.valid)
    #expect(report.issues.contains { $0.code == "field_profile" || $0.code == "invalid_order" })
  }
}

@Test func rejectsMissingExtraWrongNameTypeAndOrderForResourceToggle() {
  let valid = [
    profileField("type", .string, order: 1),
    profileField("rpc", .string, order: 2),
    profileField("updown", .boolean, order: 3),
    profileField("kDeleteActionKey", .string, order: 4),
  ]
  let invalidProfiles: [[Correlation.Field]] = [
    Array(valid.dropLast()),
    valid + [profileField("tunnel-name", .string, order: 5)],
    [
      valid[0], valid[1], profileField("updown", .number, order: 3), valid[3],
    ],
    [valid[1], valid[0], valid[2], valid[3]],
    [valid[0], valid[1], valid[2], profileField("kDeleteActionKey", .string, order: 9)],
  ]
  for fields in invalidProfiles {
    let report = syntheticReport(toggleEvent(fields: fields))
    #expect(!report.valid)
    #expect(report.issues.contains { $0.code == "field_profile" || $0.code == "invalid_order" })
  }
}

@Test func startConnectionRequiresTheCorrectHelperFamily() {
  let fields = [
    profileField("type", .string, order: 1),
    profileField("rpc", .string, order: 2),
    profileField("common", .dictionary, order: 3),
    profileField("tunnels", .array, order: 4),
  ]
  for family in [Correlation.HelperFamily?.none, .some(.ipsec)] {
    let event = Correlation.Event(
      sequence: 1,
      boundary: .xpc,
      transport: .xpc,
      direction: .guiToHelper,
      kind: .call,
      operation: .startConnection,
      helperFamily: family,
      evidenceClass: .synthetic,
      confidence: .unknown,
      fields: fields
    )
    #expect(syntheticReport(event).issues.contains { $0.code == "field_profile" })
  }
}

@Test func rejectsLiteralUnknownPathAndIdentifierLikeFieldName() throws {
  let literalPath = Correlation.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .clientToServer,
    kind: .request,
    operation: .unknown,
    method: .get,
    pathTemplate: "/users/stableidentifier",
    evidenceClass: .synthetic,
    confidence: .unknown,
    fields: [profileField("unknownField1", .unknown, order: 1)]
  )
  #expect(!syntheticReport(literalPath).valid)

  let identityField = Correlation.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .clientToServer,
    kind: .request,
    operation: .unknown,
    method: .get,
    pathTemplate: "/<UNKNOWN_PATH>",
    evidenceClass: .synthetic,
    confidence: .unknown,
    fields: [profileField("stable_identifier", .string, order: 1)]
  )
  let report = syntheticReport(identityField)
  #expect(!report.valid)
  #expect(report.issues.contains { $0.code == "unsafe_value" })
  let output = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
  #expect(!output.contains("stableidentifier"))
  #expect(!output.contains("stable_identifier"))
}

@Test func syntheticEvidenceCannotClaimConfirmedConfidence() {
  let event = Correlation.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .clientToServer,
    kind: .request,
    operation: .sessionCheck,
    method: .get,
    pathTemplate: "/vpn/user/check/session",
    evidenceClass: .synthetic,
    confidence: .confirmed,
    fields: [profileField("key", .string, order: 1, confidence: .confirmed)]
  )
  let report = syntheticReport(event)
  #expect(report.issues.filter { $0.code == "confidence_mismatch" }.count == 2)
}
