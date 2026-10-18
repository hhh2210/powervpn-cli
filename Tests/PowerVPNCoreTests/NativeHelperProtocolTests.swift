import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeHelperProtocolTests {
  @Test func strictIPv4RejectsAmbiguousForms() {
    #expect(parseStrictIPv4("11.11.37.52") == 0x0B0B_2534)
    for text in ["11.11.37", "11.11.37.052", "11.11.37.256", " 1.2.3.4", "1.2.3.4/32", ""] {
      #expect(parseStrictIPv4(text) == nil)
    }
  }

  @Test func routableHostExcludesLocalAndSpecialRanges() {
    #expect(nativeRoutableHost(parseStrictIPv4("11.11.37.52")!))
    for text in ["0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255"] {
      #expect(!nativeRoutableHost(parseStrictIPv4(text)!))
    }
  }

  @Test func listSAsSummaryReadsStateVirtualIPAndChildren() {
    let event = VICIMessage(elements: [
      .section(
        name: "powervpn-thu52-abcd",
        elements: [
          .keyValue("state", "ESTABLISHED"), .keyValue("remote-host", "192.0.2.1"),
          .list("local-vips", ["198.51.100.9"]),
          .section(
            name: "child-sas",
            elements: [
              .section(name: "selected-resource-1", elements: [.keyValue("state", "INSTALLED")])
            ]),
        ])
    ])
    let summaries = NativeIKESummary.parse([event])
    #expect(summaries.count == 1)
    #expect(summaries[0].name == "powervpn-thu52-abcd")
    #expect(summaries[0].state == "ESTABLISHED")
    #expect(summaries[0].remoteHost == "192.0.2.1")
    #expect(summaries[0].localVirtualIPs == ["198.51.100.9"])
    #expect(summaries[0].hasInstalledChild)

    let bare = NativeIKESummary.parse([
      VICIMessage(elements: [.section(name: "x", elements: [.keyValue("state", "CONNECTING")])])
    ])
    #expect(bare.first?.hasInstalledChild == false)
  }

  @Test func requestAndResponseRoundTripAsJSONLines() throws {
    let request = NativeHelperRequest(op: .routeAdd, ike: "powervpn-a", host: "192.0.2.5")
    let encoded = try JSONEncoder().encode(request)
    #expect(String(decoding: encoded, as: UTF8.self).contains("\"op\":\"route-add\""))
    #expect(try JSONDecoder().decode(NativeHelperRequest.self, from: encoded) == request)
    #expect(
      throws: DecodingError.self,
      performing: {
        _ = try JSONDecoder().decode(
          NativeHelperRequest.self, from: Data(#"{"op":"exec","host":"x"}"#.utf8))
      })
  }

  @Test func clientReportsUnavailableWithoutAHelper() {
    #expect(throws: NativeHelperClientError.unavailable) {
      _ = try NativeHelperClient.send(
        .init(op: .status), socketPath: "/tmp/powervpn-native-test-absent-\(UUID().uuidString)")
    }
  }
}
