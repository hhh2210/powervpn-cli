import Foundation
import Testing

@testable import PowerVPNCore

private func redactedTunnelSpec() -> TunnelSpec {
  TunnelSpec(
    gateway: "${GATEWAY}",
    ikeVersion: 1,
    exchangeMode: .main,
    authentication: .init(machine: "<machine-auth>", extended: "unknown"),
    localIdentifier: "<local-id>",
    remoteIdentifier: "redacted",
    ikeProposal: ["aes256-sha256-modp2048"],
    espProposal: ["aes256-sha256"],
    modeConfig: .unknown,
    vendorIds: ["<vendor-id>"],
    routes: [.init(identifier: "<route-id>", destination: "<route-cidr>")],
    resourceOperations: [.addRule, .deleteRule],
    resources: [
      .init(
        name: "<resource-name>",
        ruleIdentifier: "<rule-id>",
        remoteTrafficSelectors: ["<resource-cidr>"]
      )
    ]
  )
}

@Test func validatesClosedRedactedTunnelSpec() throws {
  let data = try JSONEncoder().encode(redactedTunnelSpec())
  let report = TunnelSpecRedactedValidator.validate(data: data)
  #expect(report.valid)
  #expect(report.issues.isEmpty)
}

@Test func rejectsRealResourceAndCredentialLikeValuesWithoutEchoingThem() throws {
  let sensitiveValue = "actual-secret-value"
  let spec = TunnelSpec(
    gateway: "vpn.example.edu",
    ikeVersion: 1,
    exchangeMode: .main,
    authentication: .init(machine: sensitiveValue, extended: "unknown"),
    localIdentifier: "<local-id>",
    remoteIdentifier: "<remote-id>",
    ikeProposal: ["aes256-sha256-modp2048"],
    espProposal: ["aes256-sha256"],
    modeConfig: .unknown,
    vendorIds: [],
    routes: [.init(identifier: "<route-id>", destination: "11.11.30.21/32")],
    resourceOperations: [.addRule, .deleteRule],
    resources: [
      .init(
        name: "login21",
        ruleIdentifier: "<rule-id>",
        remoteTrafficSelectors: ["11.11.30.21/32"]
      )
    ]
  )

  let report = TunnelSpecRedactedValidator.validate(spec)
  #expect(!report.valid)
  #expect(report.issues.contains { $0.path == "authentication.machine" })
  #expect(report.issues.contains { $0.path == "resources[0].remoteTrafficSelectors[0]" })
  let output = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
  #expect(!output.contains(sensitiveValue))
  #expect(!output.contains("11.11.30.21"))
}

@Test func rejectsUnknownSchemaFields() throws {
  let encoded = try JSONEncoder().encode(redactedTunnelSpec())
  var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  object["password"] = "must-not-be-accepted"
  let data = try JSONSerialization.data(withJSONObject: object)

  let report = TunnelSpecRedactedValidator.validate(data: data)
  #expect(!report.valid)
  #expect(report.issues == [
    TunnelSpecValidationIssue(
      path: "$",
      code: "invalid_schema",
      message: "document does not match the closed TunnelSpec schema"
    )
  ])
}

@Test func tunnelSpecModelCanRepresentFutureRuntimeValues() {
  let runtimeSpec = TunnelSpec(
    gateway: "vpn.example.edu",
    ikeVersion: 1,
    exchangeMode: .main,
    authentication: .init(machine: "certificate", extended: "xauth"),
    localIdentifier: "user@example.edu",
    remoteIdentifier: "gateway.example.edu",
    ikeProposal: ["aes256-sha256-modp2048"],
    espProposal: ["aes256-sha256"],
    modeConfig: .unknown,
    vendorIds: ["vendor-id"],
    routes: [.init(identifier: "route-1", destination: "10.0.0.1/32")],
    resourceOperations: [.addRule, .deleteRule],
    resources: [
      .init(
        name: "compute",
        ruleIdentifier: "rule-1",
        remoteTrafficSelectors: ["10.0.0.1/32"]
      )
    ]
  )

  #expect(runtimeSpec.gateway == "vpn.example.edu")
  #expect(!TunnelSpecRedactedValidator.validate(runtimeSpec).valid)
}

@Test func modelsProtocolStateReferencesRoutesAndResourceOperations() throws {
  let spec = TunnelSpec(
    gateway: "<gateway>",
    ikeVersion: 1,
    exchangeMode: .main,
    authentication: .init(machine: "unknown", extended: "unknown"),
    localIdentifier: "<local-id>",
    remoteIdentifier: "<remote-id>",
    tunnelName: "<tunnel-name>",
    virtualIP: "unknown",
    natTraversal: .unknown,
    sessionBinding: .init(storage: .opaque, identifier: "<session-binding-ref>"),
    mapID: "<map-id>",
    credentialReference: .init(storage: .keychain, identifier: "<credential-ref>"),
    ikeProposal: ["unknown"],
    espProposal: ["unknown"],
    modeConfig: .unknown,
    vendorIds: [],
    routes: [.init(identifier: "<route-id>", destination: "<route-cidr>")],
    resourceOperations: [.addRule, .deleteRule],
    resources: [
      .init(
        name: "<resource-name>",
        ruleIdentifier: "<rule-id>",
        remoteTrafficSelectors: ["<remote-selector>"]
      )
    ]
  )
  let encoded = try JSONEncoder().encode(spec)
  let decoded = try JSONDecoder().decode(TunnelSpec.self, from: encoded)

  #expect(decoded == spec)
  #expect(TunnelSpecRedactedValidator.validate(data: encoded).valid)
  #expect(decoded.modeConfig == .unknown)
  #expect(decoded.natTraversal == .unknown)
  #expect(decoded.resourceOperations == [.addRule, .deleteRule])
}

@Test func rejectsRawSessionAndCredentialReferenceValuesWithoutEchoingThem() throws {
  let rawReference = "opaque-runtime-token"
  let spec = TunnelSpec(
    gateway: "<gateway>",
    ikeVersion: 1,
    exchangeMode: .main,
    authentication: .init(machine: "unknown", extended: "unknown"),
    localIdentifier: "<local-id>",
    remoteIdentifier: "<remote-id>",
    sessionBinding: .init(storage: .opaque, identifier: rawReference),
    credentialReference: .init(storage: .keychain, identifier: rawReference),
    ikeProposal: ["unknown"],
    espProposal: ["unknown"],
    modeConfig: .unknown,
    vendorIds: [],
    resourceOperations: [.unknown],
    resources: [
      .init(name: "<resource>", remoteTrafficSelectors: ["<remote-selector>"])
    ]
  )

  let report = TunnelSpecRedactedValidator.validate(spec)
  #expect(!report.valid)
  #expect(report.issues.contains { $0.path == "sessionBinding.identifier" })
  #expect(report.issues.contains { $0.path == "credentialReference.identifier" })
  let output = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
  #expect(!output.contains(rawReference))
}
