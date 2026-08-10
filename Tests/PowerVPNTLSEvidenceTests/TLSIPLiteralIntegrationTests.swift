import Testing

@Suite(.serialized) struct TLSIPLiteralIntegrationTests {
  @Test func ipLiteralSNIAndVerifyCallbackDifferentialIsClosed() throws {
    let identity = try LocalTLSIdentityFactory.make()
    let automatic = try LocalTLSProbe.run(mode: .automatic, identity: identity)
    let explicit = try LocalTLSProbe.run(mode: .explicitIPAddress, identity: identity)

    for observation in [automatic, explicit] {
      #expect(observation.serverNameExtensionCount == 0)
      #expect(observation.verifyCallbackCount == 1)
      #expect(observation.rejectionCompletionCount == 1)
      #expect(observation.metadataChainLength == 1)
      #expect(observation.metadataLeafSHA256?.utf8.count == 64)
      #expect(!observation.clientReady)
      #expect(!observation.applicationDataSent)
    }
    #expect(automatic == explicit)
  }
}
