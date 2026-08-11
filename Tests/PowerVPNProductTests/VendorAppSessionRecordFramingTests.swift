import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppSessionRecordFramingTests {
  @Test func markerReasonsAreClosedAndHeaderScoped() {
    let valid = vendorAppSyntheticRecord()
    let unbalanced = valid.replacingOccurrences(
      of: "com.leadsec.charon-xpc", with: "other.process")
    let multiple = valid.replacingOccurrences(
      of: "charon xpc handle request:{\n",
      with: "charon xpc handle request:charon xpc handle request:{\n"
    )

    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.markerMissing)
    ) {
      _ = try vendorAppLocatedRecord("ordinary complete line\n")
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.markerUnbalanced)
    ) {
      _ = try vendorAppLocatedRecord(unbalanced)
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.markerMultiplicity)
    ) {
      _ = try vendorAppLocatedRecord(multiple)
    }
  }

  @Test func truncationEncodingSyntaxAndRootShapeAreDistinct() throws {
    let valid = vendorAppSyntheticRecord()
    let truncated = String(valid.dropLast(8))
    let duplicateKey = rpcRecord(
      "{\n  rpc = start_connection;\n  rpc = get_version;\n}")
    let nonDictionary = vendorAppSyntheticRecord(root: "(start_connection)")
    var invalidBytes = Array(
      rpcRecord("{\n  rpc = \"invalid-byte-token\";\n}").utf8
    )
    invalidBytes[invalidBytes.lastIndex(of: 0x69)!] = 0xFF
    var unrelatedInvalidBytes: [UInt8] = [0xFF, 0x0A]
    unrelatedInvalidBytes.append(contentsOf: valid.utf8)
    _ = try locatedRecord(unrelatedInvalidBytes)

    #expect(throws: VendorAppSessionSnapshotError.incomplete) {
      _ = try vendorAppLocatedRecord(truncated)
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.invalidEncoding)
    ) {
      _ = try locatedRecord(invalidBytes)
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.dictionarySyntax)
    ) {
      _ = try vendorAppLocatedRecord(duplicateKey)
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.dictionaryRootShape)
    ) {
      _ = try vendorAppLocatedRecord(nonDictionary)
    }
  }

  @Test func rpcReasonsAreDistinctAndKnownAllowlistIsPreserved() throws {
    let missing = rpcRecord("{\n  type = rpc;\n}")
    let nonScalar = rpcRecord("{\n  type = rpc;\n  rpc = (start_connection);\n}")
    let unknown = rpcRecord("{\n  type = rpc;\n  rpc = injected-rpc-token;\n}")
    let getVersion = rpcRecord("{\n  type = rpc;\n  rpc = get_version;\n}")
    let updown = rpcRecord("{\n  type = rpc;\n  rpc = updown_nc;\n}")
    let stop = rpcRecord("{\n  type = rpc;\n  rpc = stop_connection;\n}")

    #expect(throws: VendorAppSessionSnapshotError.recordRejected(.rpcMissing)) {
      _ = try vendorAppLocatedRecord(missing)
    }
    #expect(throws: VendorAppSessionSnapshotError.recordRejected(.rpcNonScalar)) {
      _ = try vendorAppLocatedRecord(nonScalar)
    }
    #expect(throws: VendorAppSessionSnapshotError.recordRejected(.rpcUnknown)) {
      _ = try vendorAppLocatedRecord(unknown)
    }
    #expect(throws: VendorAppSessionSnapshotError.recordRejected(.noStartRecord)) {
      _ = try vendorAppLocatedRecord(getVersion + updown + stop)
    }
    _ = try vendorAppLocatedRecord(getVersion + vendorAppSyntheticRecord() + updown + stop)
  }

  @Test func duplicateLogoutAndAmbiguousProducerSetsAreDistinct() throws {
    let start = vendorAppSyntheticRecord()
    let logout = rpcRecord("{\n  type = rpc;\n  rpc = logout;\n}")
    let otherProducer = rpcRecord(
      "{\n  type = rpc;\n  rpc = get_version;\n}",
      producerIdentity: "124:456"
    )
    let sameProducerDifferentThread = rpcRecord(
      "{\n  type = rpc;\n  rpc = get_version;\n}",
      producerIdentity: "123:999"
    )
    _ = try vendorAppLocatedRecord(start + sameProducerDifferentThread)

    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.duplicateStartRecord)
    ) {
      _ = try vendorAppLocatedRecord(start + start)
    }
    for records in [start + start + logout, logout + start + start] {
      #expect(throws: VendorAppSessionSnapshotError.stale) {
        _ = try vendorAppLocatedRecord(records)
      }
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.ambiguousRecordSet)
    ) {
      _ = try vendorAppLocatedRecord(start + otherProducer)
    }
  }

  @Test func recordWindowAndTerminatorRemainFailClosed() {
    let oversizedRoot =
      "{\n"
      + String(repeating: " ", count: 16_384)
      + "rpc = start_connection;\n}"
    let malformedTerminator =
      String(vendorAppSyntheticRecord().dropLast(2)) + "x\n"

    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.windowLimitReached)
    ) {
      _ = try vendorAppLocatedRecord(vendorAppSyntheticRecord(root: oversizedRoot))
    }
    #expect(
      throws: VendorAppSessionSnapshotError.recordRejected(.markerUnbalanced)
    ) {
      _ = try vendorAppLocatedRecord(malformedTerminator)
    }
  }

  @Test func parsedScalarMarkerIsNotCountedAsASecondHeader() throws {
    let root = vendorAppSyntheticRoot.replacingOccurrences(
      of: "synthetic-psk",
      with: "\"charon xpc handle request:\""
    )
    _ = try vendorAppLocatedRecord(vendorAppSyntheticRecord(root: root))
  }

  @Test func schema4ReasonsAndRequiredFieldsAreValueFree() throws {
    let injectedScalar =
      "rpc-token__line-token__value-token__offset-token__hash-token__"
      + "snapshot-token__secret-token__source-bytes-token"
    let cases: [(VendorAppSessionSnapshotError, String, String?)] = [
      (.noAppendObserved, "no_append_observed", nil),
      (.appendTooLarge, "window_limit_reached", nil),
      (.incomplete, "record_truncated", nil),
      (.recordRejected(.invalidEncoding), "invalid_encoding", nil),
      (.recordRejected(.markerMissing), "marker_missing", nil),
      (.recordRejected(.markerUnbalanced), "marker_unbalanced", nil),
      (.recordRejected(.markerMultiplicity), "marker_multiplicity", nil),
      (.recordRejected(.rpcMissing), "rpc_missing", nil),
      (.recordRejected(.rpcNonScalar), "rpc_non_scalar", nil),
      (.recordRejected(.rpcUnknown), "rpc_unknown", nil),
      (.recordRejected(.noStartRecord), "no_start_record", nil),
      (.recordRejected(.duplicateStartRecord), "duplicate_start_record", nil),
      (.stale, "logout_observed", nil),
      (.recordRejected(.ambiguousRecordSet), "ambiguous_record_set", nil),
      (.recordRejected(.dictionarySyntax), "dictionary_syntax", nil),
      (.malformed, "dictionary_root_shape", nil),
      (
        .requiredFieldMissing(.commonGateway),
        "required_field_missing",
        "common_gateway"
      ),
      (
        .requiredFieldWrongType(.routeNetwork),
        "required_field_wrong_type",
        "route_net"
      ),
    ]
    let baseKeys: Set<String> = [
      "assurance", "baselineStable", "containsSecrets", "cursorPersisted",
      "exactReceiverTerminated", "forceTerminationAccepted", "normalQuitRequested",
      "officialAppLaunched", "officialAppStillRunning", "onboardingMode", "outcome",
      "proofPersisted", "resourceDisplayName", "schemaVersion", "snapshotSerialized",
      "sourceObservation", "sourceSnapshotComplete",
    ]

    #expect(Set(cases.map(\.1)).count == cases.count)
    for (error, reason, field) in cases {
      let result = report(
        .sourceNotReady,
        sourceDiagnosis: VendorAppNonLogoutHandoffSourceDiagnosis(error)
      )
      let data = try JSONEncoder().encode(result)
      let object = try #require(
        JSONSerialization.jsonObject(with: data) as? [String: Any]
      )
      let encoded = String(decoding: data, as: UTF8.self)
      let expectedKeys =
        field == nil ? baseKeys : baseKeys.union(["sourceRequiredField"])

      #expect(object["schemaVersion"] as? Int == 4)
      #expect(Set(object.keys) == expectedKeys)
      #expect(object["sourceObservation"] as? String == reason)
      #expect(object["sourceRequiredField"] as? String == field)
      #expect(object["containsSecrets"] as? Bool == false)
      #expect(object["snapshotSerialized"] as? Bool == false)
      for forbidden in [
        injectedScalar, "rpc-token", "line-token", "value-token", "offset-token",
        "hash-token", "snapshot-token", "secret-token", "source-bytes-token",
        "injected-field", "injected-value",
      ] {
        #expect(!encoded.contains(forbidden))
      }
    }
  }

  private func rpcRecord(
    _ root: String,
    producerIdentity: String = "123:456"
  ) -> String {
    vendorAppSyntheticRecord(root: root).replacingOccurrences(
      of: "[123:456]",
      with: "[\(producerIdentity)]"
    )
  }

  private func locatedRecord(_ bytes: [UInt8]) throws -> VendorAppSessionLocatedRecord {
    try bytes.withUnsafeBytes(VendorAppSessionRecordFraming.singleStartRecord)
  }
}
