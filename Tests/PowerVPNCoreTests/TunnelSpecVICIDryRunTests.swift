import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct TunnelSpecVICIDryRunTests {
  @Test func buildsExactRedactedIKEv1MainModeLoadConnTree() throws {
    let spec = viciDryRunSpec()
    let artifact = try TunnelSpecVICIDryRun.build(spec)
    let expected = VICINamedRequest(
      command: "load-conn",
      message: VICIMessage(elements: [
        .section(
          name: "<tunnel-name>",
          elements: [
            .keyValue("version", "1"),
            .keyValue("aggressive", "no"),
            .list("remote_addrs", ["${GATEWAY}"]),
            .list("proposals", ["aes128-sha1-modp1024"]),
            .section(
              name: "local",
              elements: [
                .keyValue("auth", "psk"),
                .keyValue("id", "<local-identifier>"),
              ]
            ),
            .section(
              name: "remote",
              elements: [
                .keyValue("auth", "psk"),
                .keyValue("id", "<remote-identifier>"),
              ]
            ),
            .section(
              name: "children",
              elements: [
                .section(
                  name: "<resource-name>",
                  elements: [
                    .list("local_ts", ["dynamic"]),
                    .list("remote_ts", ["<resource-cidr>"]),
                    .list("esp_proposals", ["aes128-sha1"]),
                    .keyValue("start_action", "none"),
                  ]
                )
              ]
            ),
          ]
        )
      ])
    )

    #expect(artifact.request == expected)
    #expect(try VICINamedRequest.decode(payload: artifact.encodedRequestPayload) == expected)
    #expect(artifact.encodedRequestPayload.first == VICINamedRequest.commandRequestOperation)
    #expect(artifact.report.payloadByteCount == artifact.encodedRequestPayload.count)
    #expect(artifact.report.payloadSHA256.count == 64)
  }

  @Test func reportsOnlyNonSensitiveMetadataAndNoSideEffects() throws {
    let artifact = try TunnelSpecVICIDryRun.build(viciDryRunSpec())
    let metadata = artifact.report.metadata

    #expect(artifact.report.mode == "pure_swift_vici_dry_run")
    #expect(metadata.operation == "load-conn")
    #expect(metadata.credentialStorage == "keychain")
    #expect(!metadata.credentialIdentifierSerialized)
    #expect(!metadata.credentialIdentifierDereferenced)
    #expect(!metadata.credentialResolved)
    #expect(!metadata.secretRead)
    #expect(!metadata.secretSerialized)
    #expect(!metadata.transportLengthIncluded)
    #expect(metadata.startAction == "none")
    #expect(metadata.resourceOperations == ["ADDRULE", "DELRULE"])
    #expect(metadata.resourceCount == 1)
    #expect(metadata.ruleIdentifierPresentCount == 1)
    #expect(metadata.resourceRuleWireBinding == "unresolved_cp4b")
    #expect(!metadata.resourceRuleMetadataSerialized)
    #expect(artifact.report.sideEffects.allFalse)

    let credentialIdentifier = "<credential-reference>"
    let ruleIdentifier = "<rule-identifier>"
    let mapID = "<map-id>"
    let reportJSON = try JSONEncoder().encode(artifact.report)
    for sensitiveMetadata in [credentialIdentifier, ruleIdentifier, mapID] {
      #expect(!artifact.encodedRequestPayload.contains(Data(sensitiveMetadata.utf8)))
      #expect(!reportJSON.contains(Data(sensitiveMetadata.utf8)))
    }
  }

  @Test func acceptsMemoryCredentialStorageWithoutResolvingIt() throws {
    let artifact = try TunnelSpecVICIDryRun.build(
      viciDryRunSpec(credentialReference: .init(storage: .memory, identifier: "<memory-ref>"))
    )
    #expect(artifact.report.metadata.credentialStorage == "memory")
    #expect(!artifact.report.metadata.credentialIdentifierDereferenced)
    #expect(!artifact.report.metadata.credentialResolved)
    #expect(!artifact.report.metadata.secretRead)
  }

  @Test func rejectsUnsupportedTunnelAndCredentialProfilesWithoutEchoingInput() throws {
    try expectDryRunError(.unsupportedIKEVersion) {
      try TunnelSpecVICIDryRun.build(viciDryRunSpec(ikeVersion: 2))
    }
    try expectDryRunError(.unsupportedExchangeMode) {
      try TunnelSpecVICIDryRun.build(viciDryRunSpec(exchangeMode: .aggressive))
    }
    try expectDryRunError(.unsupportedAuthentication) {
      try TunnelSpecVICIDryRun.build(viciDryRunSpec(machineAuthentication: "unknown"))
    }
    try expectDryRunError(.missingTunnelName) {
      try TunnelSpecVICIDryRun.build(viciDryRunSpec(tunnelName: nil))
    }
    try expectDryRunError(.missingCredentialReference) {
      try TunnelSpecVICIDryRun.build(viciDryRunSpec(credentialReference: nil))
    }
    try expectDryRunError(.unsupportedCredentialStorage) {
      try TunnelSpecVICIDryRun.build(
        viciDryRunSpec(credentialReference: .init(storage: .opaque, identifier: "<opaque-ref>"))
      )
    }

    let rawIdentifier = "actual-sensitive-credential-reference"
    do {
      _ = try TunnelSpecVICIDryRun.build(
        viciDryRunSpec(
          credentialReference: .init(storage: .keychain, identifier: rawIdentifier)
        )
      )
      #expect(Bool(false), "expected redaction failure")
    } catch {
      #expect(
        String(describing: error)
          == String(describing: TunnelSpecVICIDryRunError.unsafeRedactedSpec)
      )
      #expect(!String(describing: error).contains(rawIdentifier))
    }
  }

  @Test func requiresExactlyOneSelectorPerResource() throws {
    try expectDryRunError(.invalidRemoteSelectorCount) {
      try TunnelSpecVICIDryRun.build(viciDryRunSpec(remoteSelectors: []))
    }
    try expectDryRunError(.invalidRemoteSelectorCount) {
      try TunnelSpecVICIDryRun.build(
        viciDryRunSpec(remoteSelectors: ["<resource-cidr-a>", "<resource-cidr-b>"])
      )
    }
  }

  @Test func buildsFromClosedJSONAndRejectsUnknownFields() throws {
    let encoded = try JSONEncoder().encode(viciDryRunSpec())
    #expect(try TunnelSpecVICIDryRun.build(data: encoded).report.metadata.operation == "load-conn")

    var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    object["secret"] = "not-accepted"
    let unknownFieldData = try JSONSerialization.data(withJSONObject: object)
    try expectDryRunError(.invalidSchema) {
      try TunnelSpecVICIDryRun.build(data: unknownFieldData)
    }
  }

  @Test func rejectsDuplicateObjectKeysBeforeFoundationCanonicalization() throws {
    let encoded = try JSONEncoder().encode(viciDryRunSpec())
    let duplicateRoot = prependObjectMember(
      #""gateway":"<duplicate>""#,
      to: encoded
    )
    try expectDryRunError(.invalidSchema) {
      try TunnelSpecVICIDryRun.build(data: duplicateRoot)
    }

    let escapedDuplicateRoot = prependObjectMember(
      #""\u0067ateway":"<duplicate>""#,
      to: encoded
    )
    try expectDryRunError(.invalidSchema) {
      try TunnelSpecVICIDryRun.build(data: escapedDuplicateRoot)
    }

    let marker = Data(#""credentialReference":{"#.utf8)
    let range = try #require(encoded.range(of: marker))
    var duplicateNested = encoded
    duplicateNested.insert(
      contentsOf: Data(#""identifier":"<duplicate>","#.utf8),
      at: range.upperBound
    )
    try expectDryRunError(.invalidSchema) {
      try TunnelSpecVICIDryRun.build(data: duplicateNested)
    }
  }

  @Test func boundedFileEntryPointsRejectOversizedDocuments() throws {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(
      "powervpn-tunnel-spec-\(UUID().uuidString).json"
    )
    defer { try? FileManager.default.removeItem(at: url) }
    try Data(
      repeating: 0x20,
      count: TunnelSpecRedactedValidator.maximumDocumentBytes + 1
    ).write(to: url)

    let validation = try TunnelSpecRedactedValidator.validate(contentsOf: url)
    #expect(validation.issues.first?.code == "size_limit")
    try expectDryRunError(.documentTooLarge) {
      try TunnelSpecVICIDryRun.build(contentsOf: url)
    }
  }
}

private func viciDryRunSpec(
  ikeVersion: Int = 1,
  exchangeMode: TunnelSpec.ExchangeMode = .main,
  machineAuthentication: String = "psk",
  tunnelName: String? = "<tunnel-name>",
  credentialReference: TunnelSpec.ExternalReference? = .init(
    storage: .keychain,
    identifier: "<credential-reference>"
  ),
  remoteSelectors: [String] = ["<resource-cidr>"]
) -> TunnelSpec {
  TunnelSpec(
    gateway: "${GATEWAY}",
    ikeVersion: ikeVersion,
    exchangeMode: exchangeMode,
    authentication: .init(machine: machineAuthentication, extended: "unknown"),
    localIdentifier: "<local-identifier>",
    remoteIdentifier: "<remote-identifier>",
    tunnelName: tunnelName,
    virtualIP: "<virtual-ip>",
    natTraversal: .observed,
    sessionBinding: .init(storage: .opaque, identifier: "<session-binding-reference>"),
    mapID: "<map-id>",
    credentialReference: credentialReference,
    ikeProposal: ["aes128-sha1-modp1024"],
    espProposal: ["aes128-sha1"],
    modeConfig: .unknown,
    vendorIds: ["unknown"],
    routes: [.init(identifier: "<route-identifier>", destination: "<route-cidr>")],
    resourceOperations: [.addRule, .deleteRule],
    resources: [
      .init(
        name: "<resource-name>",
        ruleIdentifier: "<rule-identifier>",
        remoteTrafficSelectors: remoteSelectors
      )
    ]
  )
}

private func expectDryRunError<T>(
  _ expected: TunnelSpecVICIDryRunError,
  _ operation: () throws -> T
) throws {
  do {
    _ = try operation()
    #expect(Bool(false), "expected TunnelSpec VICI dry-run error")
  } catch let error as TunnelSpecVICIDryRunError {
    #expect(error == expected)
  }
}

private func prependObjectMember(_ member: String, to data: Data) -> Data {
  #expect(data.first == 0x7B)
  var result = Data([0x7B])
  result.append(Data(member.utf8))
  result.append(0x2C)
  result.append(data.dropFirst())
  return result
}
