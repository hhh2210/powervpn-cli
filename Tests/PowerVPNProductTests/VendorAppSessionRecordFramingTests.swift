import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppSessionRecordFramingTests {
  @Test func exactProducerAndRecordSuffixAreRequired() throws {
    _ = try vendorAppLocatedRecord(vendorAppSyntheticRecord())
    let valid = vendorAppSyntheticRecord()
    let malformed = [
      valid.replacingOccurrences(of: "com.leadsec.charon-xpc", with: "other.process"),
      valid.replacingOccurrences(of: "[123:456]", with: "[0123:456]"),
      valid.replacingOccurrences(of: "request:{\n", with: "request: {\n"),
      valid.replacingOccurrences(of: "request:{\n", with: "request:{ "),
      String(valid.dropLast(2)) + "x\n",
    ]
    for value in malformed {
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppLocatedRecord(value)
      }
    }
  }

  @Test func truncatedOrDuplicateStartNeverFallsBack() throws {
    let valid = vendorAppSyntheticRecord()
    let truncated = String(valid.dropLast(8))
    for value in [valid + truncated, valid + valid] {
      #expect(throws: VendorAppSessionSnapshotError.self) {
        _ = try vendorAppLocatedRecord(value)
      }
    }
  }

  @Test func markerInsideParsedScalarIsNotASecondRecord() throws {
    let root = vendorAppSyntheticRoot.replacingOccurrences(
      of: "synthetic-psk",
      with: "\"charon xpc handle request:\""
    )
    _ = try vendorAppLocatedRecord(vendorAppSyntheticRecord(root: root))
  }
}
