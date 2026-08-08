import Testing

@testable import PowerVPNCore

private func staticField(
  _ name: String,
  _ type: ProtocolCorrelationDocument.FieldType,
  order: Int
) -> ProtocolCorrelationDocument.Field {
  ProtocolCorrelationDocument.Field(
    name: name,
    type: type,
    order: order,
    evidenceClass: .staticBinary,
    confidence: .confirmed
  )
}

@Test func staticHTTPResponseMayKeepUnobservedStatusUnknown() {
  let event = ProtocolCorrelationDocument.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .serverToClient,
    kind: .response,
    operation: .resourceList,
    method: .get,
    pathTemplate: "/vpn/user/portal/intergration.xml",
    evidenceClass: .staticBinary,
    confidence: .confirmed
  )
  let document = ProtocolCorrelationDocument(source: .staticBinary, events: [event])
  #expect(ProtocolCorrelationRedactedValidator.validate(document).valid)
}

@Test func runtimeHTTPResponseRequiresObservedStatus() {
  let event = ProtocolCorrelationDocument.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .serverToClient,
    kind: .response,
    operation: .sessionCheck,
    method: .get,
    pathTemplate: "/vpn/user/check/session",
    evidenceClass: .runtimeMetadata,
    confidence: .confirmed
  )
  let document = ProtocolCorrelationDocument(source: .runtimeMetadata, events: [event])
  let report = ProtocolCorrelationRedactedValidator.validate(document)
  #expect(report.issues.contains { $0.code == "missing_runtime_metadata" })
}

@Test func resourceToggleOperationsRemainClosedXPCMetadata() {
  let cases:
    [(
      ProtocolCorrelationDocument.Operation,
      ProtocolCorrelationDocument.HelperFamily,
      [ProtocolCorrelationDocument.Field]
    )] = [
      (
        .resourceToggleNC,
        .charon,
        [
          staticField("type", .string, order: 1), staticField("rpc", .string, order: 2),
          staticField("updown", .boolean, order: 3),
          staticField("kDeleteActionKey", .string, order: 4),
        ]
      ),
      (
        .resourceToggleIPSec,
        .ipsec,
        [
          staticField("type", .string, order: 1), staticField("rpc", .string, order: 2),
          staticField("updown", .boolean, order: 3),
          staticField("kDeleteActionKey", .string, order: 4),
        ]
      ),
      (
        .queryTunnelName,
        .ipsec,
        [
          staticField("type", .string, order: 1), staticField("rpc", .string, order: 2),
          staticField("get", .string, order: 3),
        ]
      ),
      (
        .getVersion,
        .charon,
        [staticField("type", .string, order: 1), staticField("rpc", .string, order: 2)]
      ),
    ]
  for operation in cases {
    let event = ProtocolCorrelationDocument.Event(
      sequence: 1,
      boundary: .xpc,
      transport: .xpc,
      direction: .guiToHelper,
      kind: .call,
      operation: operation.0,
      helperFamily: operation.1,
      evidenceClass: .staticBinary,
      confidence: .confirmed,
      fields: operation.2
    )
    let document = ProtocolCorrelationDocument(source: .staticBinary, events: [event])
    #expect(ProtocolCorrelationRedactedValidator.validate(document).valid)
  }
}

@Test func logoutHasAnExactKnownHTTPSShape() {
  let event = ProtocolCorrelationDocument.Event(
    sequence: 1,
    boundary: .controlPlane,
    transport: .https,
    direction: .clientToServer,
    kind: .request,
    operation: .logout,
    method: .post,
    pathTemplate: "/vpn/user/logout",
    evidenceClass: .staticBinary,
    confidence: .confirmed
  )
  let document = ProtocolCorrelationDocument(source: .staticBinary, events: [event])
  #expect(ProtocolCorrelationRedactedValidator.validate(document).valid)
}
