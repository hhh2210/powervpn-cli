import Testing
@preconcurrency import XPC

@testable import PowerVPNCore

@Suite struct VendorXPCEnvelopeTests {
  @Test func buildsOnlyTheLockedOrderedGetVersionEnvelope() throws {
    #expect(
      VendorXPCGetVersionRequestContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "get_version"),
      ])

    let request = VendorXPCWireCodec.makeGetVersionRequest()
    #expect(xpc_get_type(request) == XPC_TYPE_DICTIONARY)
    #expect(xpc_dictionary_get_count(request) == 2)
    let type = try #require(xpc_dictionary_get_value(request, "type"))
    let rpc = try #require(xpc_dictionary_get_value(request, "rpc"))
    #expect(xpc_get_type(type) == XPC_TYPE_STRING)
    #expect(xpc_get_type(rpc) == XPC_TYPE_STRING)
    #expect(matches(type, bytes: [0x72, 0x70, 0x63]))
    #expect(
      matches(
        rpc,
        bytes: [0x67, 0x65, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e]
      ))
    #expect(xpc_dictionary_get_value(request, "start_connection") == nil)
  }

  @Test func acceptsOnlyTheExactLockedBusinessEvent() throws {
    let reply = businessReply(version: [0x32, 0x34, 0x35, 0x37, 0x32], success: true)
    let event = VendorXPCWireCodec.connectionEvent(reply, peerPID: 321)
    guard case .business(let decoded, let peerPID) = event else {
      Issue.record("expected exact business event")
      return
    }
    #expect(decoded.versionByteLength == 5)
    #expect(decoded.versionMatchesLockedBuild)
    #expect(decoded.getVersionSuccess)
    #expect(peerPID == 321)
  }

  @Test func preservesMismatchAndNegativeReplyWithoutVersionMaterialization() {
    let mismatch = VendorXPCWireCodec.connectionEvent(
      businessReply(version: [0x32, 0x34, 0x35, 0x37, 0x33], success: true),
      peerPID: 1
    )
    let negative = VendorXPCWireCodec.connectionEvent(
      businessReply(version: [0x32, 0x34, 0x35, 0x37, 0x32], success: false),
      peerPID: 2
    )

    guard case .business(let mismatchReply, _) = mismatch,
      case .business(let negativeReply, _) = negative
    else {
      Issue.record("expected structurally valid business events")
      return
    }
    #expect(mismatchReply.versionByteLength == 5)
    #expect(!mismatchReply.versionMatchesLockedBuild)
    #expect(negativeReply.versionMatchesLockedBuild)
    #expect(!negativeReply.getVersionSuccess)
    #expect(!isCodableType(VendorXPCGetVersionEvidence.self))
  }

  @Test func rejectsMissingExtraAndWrongTypedBusinessFields() {
    let missing = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(missing, "version", "24572")

    let extra = businessReply(version: [0x32, 0x34, 0x35, 0x37, 0x32], success: true)
    xpc_dictionary_set_bool(extra, "extra", true)

    let wrongType = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_int64(wrongType, "version", 24_572)
    xpc_dictionary_set_bool(wrongType, "get_version", true)

    for value in [missing, extra, wrongType] {
      #expect(
        VendorXPCWireCodec.connectionEvent(value, peerPID: 9)
          == .malformedBusinessEvent)
    }
  }

  @Test func keepsDispatcherTailAndReplyAcknowledgementOutOfBusinessResults() {
    let empty = xpc_dictionary_create(nil, nil, 0)
    #expect(
      VendorXPCWireCodec.connectionEvent(empty, peerPID: 7) == .emptyDispatcherTail)
    #expect(VendorXPCWireCodec.replyCallback(empty) == .emptyAcknowledgement)

    let full = businessReply(version: [0x32, 0x34, 0x35, 0x37, 0x32], success: true)
    #expect(VendorXPCWireCodec.replyCallback(full) == .unexpectedPayload)
  }

  @Test func classifiesErrorsFromEitherRawCallbackPath() {
    #expect(
      VendorXPCWireCodec.connectionEvent(
        XPC_ERROR_CONNECTION_INTERRUPTED,
        peerPID: 0
      ) == .connectionInterrupted)
    #expect(
      VendorXPCWireCodec.replyCallback(XPC_ERROR_CONNECTION_INTERRUPTED)
        == .connectionInterrupted)
    #expect(
      VendorXPCWireCodec.connectionEvent(XPC_ERROR_CONNECTION_INVALID, peerPID: 0)
        == .connectionInvalid)
    #expect(
      VendorXPCWireCodec.replyCallback(XPC_ERROR_CONNECTION_INVALID) == .connectionInvalid)
    #expect(
      VendorXPCWireCodec.connectionEvent(XPC_ERROR_TERMINATION_IMMINENT, peerPID: 0)
        == .unexpectedXPCError)
    #expect(
      VendorXPCWireCodec.replyCallback(XPC_ERROR_TERMINATION_IMMINENT)
        == .unexpectedXPCError)

    if #available(macOS 15.0, *) {
      #expect(
        VendorXPCWireCodec.connectionEvent(
          XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT,
          peerPID: 0
        ) == .peerCodeSigningRequirement)
      #expect(
        VendorXPCWireCodec.replyCallback(XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT)
          == .peerCodeSigningRequirement)
    }
  }

  @Test func rejectsNonDictionaryConnectionAndReplyObjects() {
    let value = xpc_string_create("not-a-dictionary")
    #expect(
      VendorXPCWireCodec.connectionEvent(value, peerPID: 1)
        == .unexpectedConnectionEvent)
    #expect(VendorXPCWireCodec.replyCallback(value) == .unexpectedPayload)
  }

  @Test func inconsistentEvidenceCannotClaimAcceptance() {
    let evidence = VendorXPCGetVersionEvidence(
      outcome: .accepted,
      versionByteLength: 5,
      versionMatchesLockedBuild: false,
      getVersionSuccess: true,
      replyPeerGenerationValidated: true,
      connectionCancelRequested: true
    )
    #expect(!evidence.accepted)

    let missingBinding = VendorXPCGetVersionEvidence(
      outcome: .accepted,
      versionByteLength: 5,
      versionMatchesLockedBuild: true,
      getVersionSuccess: true,
      replyPeerGenerationValidated: false,
      connectionCancelRequested: true
    )
    #expect(!missingBinding.accepted)
  }
}

private func businessReply(version: [UInt8], success: Bool) -> xpc_object_t {
  let reply = xpc_dictionary_create(nil, nil, 0)
  var terminated = version + [0]
  terminated.withUnsafeMutableBytes { bytes in
    xpc_dictionary_set_string(
      reply,
      "version",
      bytes.baseAddress!.assumingMemoryBound(to: CChar.self)
    )
  }
  xpc_dictionary_set_bool(reply, "get_version", success)
  return reply
}

private func matches(_ value: xpc_object_t, bytes: [UInt8]) -> Bool {
  guard xpc_get_type(value) == XPC_TYPE_STRING,
    xpc_string_get_length(value) == bytes.count,
    let pointer = xpc_string_get_string_ptr(value)
  else { return false }
  return bytes.indices.allSatisfy { UInt8(bitPattern: pointer[$0]) == bytes[$0] }
}

private func isCodableType(_ type: Any.Type) -> Bool {
  type is any Codable.Type
}
