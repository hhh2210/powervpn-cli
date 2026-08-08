import Foundation
import Testing

@testable import PowerVPNCore

private typealias Correlation = ProtocolCorrelationDocument

private func boundaryField(
  _ name: String,
  evidenceClass: Correlation.EvidenceClass
) -> Correlation.Field {
  Correlation.Field(
    name: name,
    type: .string,
    order: 1,
    evidenceClass: evidenceClass,
    confidence: .unknown
  )
}

@Test func boundedFileValidationRejectsOversizedInput() throws {
  let url = FileManager.default.temporaryDirectory.appendingPathComponent(
    "powervpn-correlation-\(UUID().uuidString).json"
  )
  defer { try? FileManager.default.removeItem(at: url) }
  try Data(
    repeating: 0x20,
    count: ProtocolCorrelationRedactedValidator.maximumDocumentBytes + 2
  ).write(to: url)
  let report = try ProtocolCorrelationRedactedValidator.validate(contentsOf: url)
  #expect(report.issues.first?.code == "size_limit")
}

@Test func rejectsKnownHTTPOperationMethodOrPathDrift() {
  let cases: [(Correlation.HTTPMethod, String, String)] = [
    (.post, "/vpn/user/check/session", "key"),
    (.get, "/vpn/user/auth/token", "token"),
  ]
  for (method, path, fieldName) in cases {
    let event = Correlation.Event(
      sequence: 1,
      boundary: .controlPlane,
      transport: .https,
      direction: .clientToServer,
      kind: .request,
      operation: .sessionCheck,
      method: method,
      pathTemplate: path,
      evidenceClass: .synthetic,
      confidence: .unknown,
      fields: [boundaryField(fieldName, evidenceClass: .synthetic)]
    )
    let report = ProtocolCorrelationRedactedValidator.validate(
      Correlation(source: .synthetic, events: [event])
    )
    #expect(report.issues.contains { $0.code == "operation_mismatch" })
  }
}

@Test func rejectsEvidenceThatDoesNotMatchTheDeclaredSource() {
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
    confidence: .unknown,
    fields: [boundaryField("key", evidenceClass: .synthetic)]
  )
  let report = ProtocolCorrelationRedactedValidator.validate(
    Correlation(source: .runtimeMetadata, events: [event])
  )
  #expect(!report.valid)
  #expect(report.issues.allSatisfy { $0.code == "source_mismatch" })
  #expect(report.issues.count == 2)
}
