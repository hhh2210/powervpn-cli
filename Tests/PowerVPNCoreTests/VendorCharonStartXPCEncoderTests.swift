import Foundation
import Testing
@preconcurrency import XPC

@testable import PowerVPNCore

@Suite struct VendorCharonStartXPCEncoderTests {
  @Test func encodesExactRootCommonTunnelAndRouteShapes() throws {
    let fixture = EncoderFixture()
    let snapshot = try fixture.snapshot(includeOptional: true)
    let insertions = InsertionRecorder()

    try VendorCharonStartXPCEncoder(insertionObserver: insertions.observe)
      .withEncodedMessage(snapshot: snapshot) { root in
        #expect(xpc_get_type(root) == XPC_TYPE_DICTIONARY)
        #expect(hasExactKeys(root, ["type", "rpc", "common", "tunnels"]))
        #expect(try string(root, "type") == "rpc")
        #expect(try string(root, "rpc") == "start_connection")

        let common = try dictionary(root, "common")
        #expect(
          hasExactKeys(
            common,
            [
              "sessionid", "vip", "vipv6", "gateway", "ike_port", "majorVersion",
              "ike", "esp", "psk", "ike_life_time", "ipsec_life_time",
            ]))
        #expect(try string(common, "sessionid") == "client-id")
        #expect(try string(common, "vip") == "10.0.0.1")
        #expect(try string(common, "vipv6") == "::1")
        #expect(try string(common, "gateway") == "gateway")
        #expect(xpc_dictionary_get_int64(common, "ike_port") == 500)
        #expect(xpc_dictionary_get_int64(common, "majorVersion") == 2)
        #expect(try string(common, "ike") == "ike-proposal")
        #expect(try string(common, "esp") == "esp-proposal")
        #expect(try string(common, "psk") == "synthetic-psk")
        #expect(xpc_dictionary_get_int64(common, "ike_life_time") == 3_600)
        #expect(xpc_dictionary_get_int64(common, "ipsec_life_time") == 1_800)

        let tunnels = try array(root, "tunnels")
        #expect(xpc_array_get_count(tunnels) == 1)
        let tunnel = try arrayDictionary(tunnels, 0)
        #expect(
          hasExactKeys(
            tunnel,
            [
              "authority", "status", "tunnel-name", "family", "rflag", "name",
              "routes", "mapid", "negotiate-mode",
            ]))
        #expect(xpc_dictionary_get_int64(tunnel, "authority") == 1)
        #expect(xpc_dictionary_get_int64(tunnel, "status") == 2)
        #expect(try string(tunnel, "tunnel-name") == "tunnel")
        #expect(xpc_dictionary_get_int64(tunnel, "family") == 4)
        #expect(xpc_dictionary_get_int64(tunnel, "rflag") == 0)
        #expect(try string(tunnel, "name").isEmpty)
        #expect(try string(tunnel, "mapid") == "map")
        #expect(xpc_dictionary_get_int64(tunnel, "negotiate-mode") == 1)

        let routes = try array(tunnel, "routes")
        #expect(xpc_array_get_count(routes) == 2)
        let integerRoute = try arrayDictionary(routes, 0)
        #expect(hasExactKeys(integerRoute, ["net", "prfix"]))
        #expect(try string(integerRoute, "net") == "10.0.0.0")
        #expect(xpc_get_type(try value(integerRoute, "prfix")) == XPC_TYPE_INT64)
        #expect(xpc_dictionary_get_int64(integerRoute, "prfix") == 24)
        let textRoute = try arrayDictionary(routes, 1)
        #expect(hasExactKeys(textRoute, ["net", "prfix"]))
        #expect(try string(textRoute, "net") == "2001:db8::")
        #expect(xpc_get_type(try value(textRoute, "prfix")) == XPC_TYPE_STRING)
        #expect(try string(textRoute, "prfix") == "64")
      }

    #expect(insertions.fields(in: .root) == [.type, .rpc, .common, .tunnels])
    #expect(
      insertions.fields(in: .common) == [
        .sessionID, .vip, .vipv6, .gateway, .ikePort, .majorVersion, .ike, .esp,
        .psk, .ikeLifetime, .ipsecLifetime,
      ])
    #expect(
      insertions.fields(in: .tunnel) == [
        .authority, .status, .tunnelName, .family, .resourceFlag, .name, .routes,
        .mapID, .negotiateMode,
      ])
    #expect(
      insertions.fields(in: .route) == [
        .routeNetwork, .routePrefix, .routeNetwork, .routePrefix,
      ])
  }

  @Test func omitsOnlyProvenOptionalFieldsAndForbiddenKeys() throws {
    let snapshot = try EncoderFixture().snapshot(includeOptional: false)

    try snapshot.withEncodedStartMessage { root in
      let common = try dictionary(root, "common")
      let tunnel = try arrayDictionary(try array(root, "tunnels"), 0)
      #expect(xpc_dictionary_get_value(common, "vip") == nil)
      #expect(xpc_dictionary_get_value(common, "vipv6") == nil)
      #expect(xpc_dictionary_get_value(tunnel, "negotiate-mode") == nil)
      for forbidden in ["hostItem", "natt_port", "dns", "dnssrv", "DNS_INFO"] {
        #expect(xpc_dictionary_get_value(root, forbidden) == nil)
        #expect(xpc_dictionary_get_value(common, forbidden) == nil)
        #expect(xpc_dictionary_get_value(tunnel, forbidden) == nil)
      }
    }
  }

  @Test func clearsEveryTemporaryCStringBuffer() throws {
    let recorder = EraseRecorder()
    let snapshot = try EncoderFixture().snapshot(includeOptional: true)

    try VendorCharonStartXPCEncoder(eraseObserver: recorder.observe)
      .withEncodedMessage(snapshot: snapshot) { _ in }

    #expect(recorder.count == 13)
    #expect(recorder.allZero)
  }

  @Test func encoderRevalidatesMaterialAfterSnapshotValidation() throws {
    let fixture = EncoderFixture()
    let session = EncoderTextMaterial("client-id")
    let snapshot = try fixture.snapshot(session: session, includeOptional: false)
    session.replace(with: Array("bad\0value".utf8))

    #expect(throws: VendorCharonStartEncodingError.invalidTextMaterial(.sessionID)) {
      try snapshot.withEncodedStartMessage { _ in }
    }

    session.replace(
      with: Array(repeating: 0x61, count: VendorCharonStartValidator.maximumTextBytes + 1))
    #expect(throws: VendorCharonStartEncodingError.invalidTextMaterial(.sessionID)) {
      try snapshot.withEncodedStartMessage { _ in }
    }
  }

  @Test func exactEmptyTunnelNameIsAllowedButEmptySessionIsNot() throws {
    let fixture = EncoderFixture()
    let valid = try fixture.snapshot(includeOptional: false)
    try valid.withEncodedStartMessage { root in
      let tunnel = try arrayDictionary(try array(root, "tunnels"), 0)
      #expect(try string(tunnel, "name").isEmpty)
    }

    let emptySession = EncoderTextMaterial("")
    let validation = fixture.validation(session: emptySession, includeOptional: false)
    #expect(validation.firstMissingField == .sessionID)
    #expect(validation.snapshot == nil)
  }

  @Test func incompleteAndMixedCandidatesNeverExposeAnEncoderSnapshot() {
    #expect(VendorCharonStartValidator.validate(VendorCharonStartCandidate()).snapshot == nil)

    let first = EncoderFixture()
    let second = EncoderFixture()
    let mixed = VendorCharonStartCandidate(
      lineage: first.lineage,
      common: first.common(session: EncoderTextMaterial("client-id"), includeOptional: false),
      tunnels: [second.tunnel(includeOptional: false)]
    )
    let validation = VendorCharonStartValidator.validate(mixed)
    #expect(validation.lineageStatus == .mixed)
    #expect(validation.snapshot == nil)
  }

  @Test func materialSourceCasesHaveExactValueFreeNames() {
    #expect(
      VendorCharonStartMaterialSource.authenticatedPortalOrigin.rawValue
        == "authenticated_portal_origin")
    #expect(
      VendorCharonStartMaterialSource.authenticatedPortalMetadata.rawValue
        == "authenticated_portal_metadata")
  }
}

private final class EncoderTextMaterial: @unchecked Sendable, VendorCharonStartTextMaterial {
  private let lock = NSLock()
  private var storage: [UInt8]

  init(_ value: String) {
    storage = Array(value.utf8)
  }

  var byteCount: Int { lock.withLock { storage.count } }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try lock.withLock { try storage.withUnsafeBytes(body) }
  }

  func replace(with bytes: [UInt8]) {
    lock.withLock { storage = bytes }
  }
}

private struct EncoderFixture {
  let lineage = VendorCharonStartLineage()

  func validation(
    session: EncoderTextMaterial = EncoderTextMaterial("client-id"),
    includeOptional: Bool
  ) -> VendorCharonStartValidation {
    VendorCharonStartValidator.validate(
      VendorCharonStartCandidate(
        lineage: lineage,
        common: common(session: session, includeOptional: includeOptional),
        tunnels: [tunnel(includeOptional: includeOptional)]
      ))
  }

  func snapshot(
    session: EncoderTextMaterial = EncoderTextMaterial("client-id"),
    includeOptional: Bool
  ) throws -> VendorCharonStartSnapshot {
    guard let snapshot = validation(session: session, includeOptional: includeOptional).snapshot
    else { throw EncoderTestError.missingSnapshot }
    return snapshot
  }

  func common(
    session: EncoderTextMaterial,
    includeOptional: Bool
  ) -> VendorCharonStartCommonCandidate {
    VendorCharonStartCommonCandidate(
      sessionID: text(session),
      vip: includeOptional ? text("10.0.0.1") : nil,
      vipv6: includeOptional ? text("::1") : nil,
      gateway: text("gateway"),
      ikePort: integer(500),
      majorVersion: integer(2),
      ike: text("ike-proposal"),
      esp: text("esp-proposal"),
      psk: text("synthetic-psk"),
      ikeLifetime: integer(3_600),
      ipsecLifetime: integer(1_800)
    )
  }

  func tunnel(includeOptional: Bool) -> VendorCharonStartTunnelCandidate {
    VendorCharonStartTunnelCandidate(
      authority: integer(1),
      status: integer(2),
      tunnelName: text("tunnel"),
      family: integer(4),
      resourceFlag: integer(0),
      name: text(""),
      routes: [
        VendorCharonStartRouteCandidate(network: text("10.0.0.0"), prefix: prefix(24)),
        VendorCharonStartRouteCandidate(
          network: text("2001:db8::"),
          prefix: decimalPrefix("64")
        ),
      ],
      mapID: text("map"),
      negotiateMode: includeOptional ? integer(1) : nil
    )
  }

  private func text(_ value: String) -> VendorCharonStartTextValue {
    text(EncoderTextMaterial(value))
  }

  private func text(_ value: EncoderTextMaterial) -> VendorCharonStartTextValue {
    VendorCharonStartTextValue(
      value: value,
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  private func integer(_ value: Int32) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: value,
      source: .authenticatedPortalMetadata,
      lineage: lineage
    )
  }

  private func prefix(_ value: Int32) -> VendorCharonStartPrefixValue {
    VendorCharonStartPrefixValue(
      value: .integer(value),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  private func decimalPrefix(_ value: String) -> VendorCharonStartPrefixValue {
    VendorCharonStartPrefixValue(
      value: .decimalText(EncoderTextMaterial(value)),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }
}
