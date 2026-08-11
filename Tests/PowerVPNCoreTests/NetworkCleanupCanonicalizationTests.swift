import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupCanonicalizationTests {
  @Test func defaultRouteUsesStableKeyOrderAndRejectsDuplicateFields() throws {
    let first = Data(
      """
      route to: default
      destination: default
      mask: default
      gateway: 192.0.2.1
      interface: utun8
      flags: <UP,GATEWAY,DONE,STATIC>
      """.utf8)
    let reordered = Data(
      """
      flags: <UP,GATEWAY,DONE,STATIC>
      interface:   utun8
      gateway: 192.0.2.1
      destination: default
      mask: default
      """.utf8)

    let a = try NetworkDefaultRouteCanonicalizer.canonicalize(first)
    let b = try NetworkDefaultRouteCanonicalizer.canonicalize(reordered)
    #expect(a == b)
    #expect(a.itemCount == 1)
    #expect(a.sha256?.count == 64)

    let duplicate = first + Data("\ngateway: 192.0.2.2\n".utf8)
    #expect(throws: NetworkCleanupCanonicalizationError.duplicateValue) {
      try NetworkDefaultRouteCanonicalizer.canonicalize(duplicate)
    }
  }

  @Test func defaultRouteAcceptsGatewaylessUtunButRejectsOtherIncompleteShapes() throws {
    let pointToPoint = try NetworkDefaultRouteCanonicalizer.canonicalize(
      Data("destination: default\nmask: default\ninterface: utun8\nflags: <UP>\n".utf8)
    )
    #expect(pointToPoint.isObserved)
    for interface in ["en0", "utun", "utunfoo", "utun١"] {
      #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
        try NetworkDefaultRouteCanonicalizer.canonicalize(
          Data(
            "destination: default\nmask: default\ninterface: \(interface)\nflags: <UP>\n".utf8
          )
        )
      }
    }
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkDefaultRouteCanonicalizer.canonicalize(
        Data("destination: default\nflags: <UP>\n".utf8)
      )
    }
    #expect(throws: NetworkCleanupCanonicalizationError.invalidUTF8) {
      try NetworkDefaultRouteCanonicalizer.canonicalize(Data([0x61, 0x00, 0x62]))
    }
  }

  @Test func dnsNormalizesWhitespaceButPreservesResolverOrder() throws {
    let first = dnsFixture(firstServer: "192.0.2.53", secondServer: "2001:db8::53")
    let whitespace = first.replacingOccurrences(of: "  nameserver", with: "\t nameserver")
      .replacingOccurrences(of: "\n", with: "\r\n")
    let reordered = dnsFixture(firstServer: "2001:db8::53", secondServer: "192.0.2.53")

    let a = try NetworkDNSCanonicalizer.canonicalize(Data(first.utf8))
    let b = try NetworkDNSCanonicalizer.canonicalize(Data(whitespace.utf8))
    let c = try NetworkDNSCanonicalizer.canonicalize(Data(reordered.utf8))
    #expect(a == b)
    #expect(a.itemCount == 2)
    #expect(a != c)
  }

  @Test func dnsAcceptsExplicitNoConfigurationAndRejectsUnknownShape() throws {
    let empty = try NetworkDNSCanonicalizer.canonicalize(
      Data("No DNS configuration available\n".utf8)
    )
    #expect(empty.itemCount == 0)
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkDNSCanonicalizer.canonicalize(Data("nameserver: 192.0.2.1\n".utf8))
    }
    let duplicate = """
      DNS configuration
      resolver #1
      nameserver[0] : 192.0.2.1
      resolver #1
      nameserver[0] : 192.0.2.2
      """
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkDNSCanonicalizer.canonicalize(Data(duplicate.utf8))
    }
    let emptySection = """
      DNS configuration
      DNS configuration (for scoped queries)
      resolver #1
      nameserver[0] : 192.0.2.1
      """
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkDNSCanonicalizer.canonicalize(Data(emptySection.utf8))
    }
    let leadingZero = "DNS configuration\nresolver #01\nnameserver[0] : 192.0.2.1\n"
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkDNSCanonicalizer.canonicalize(Data(leadingZero.utf8))
    }
  }

  @Test func interfaceBlockOrderingIsCanonicalAndUtunDeltaIsTokenOnly() throws {
    let window = NetworkCleanupCaptureWindow(keyData: Data(repeating: 7, count: 32))
    let en0 = """
      en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
          ether aa:bb:cc:dd:ee:ff
          inet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
      """
    let utun = """
      utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
          inet6 fe80::1%utun8 prefixlen 64 scopeid 0x1a
      """
    let first = try NetworkInterfaceCanonicalizer.canonicalize(
      Data("\(en0)\n\(utun)".utf8),
      window: window
    )
    let reordered = try NetworkInterfaceCanonicalizer.canonicalize(
      Data("\(utun)\n\(en0)".utf8),
      window: window
    )
    let changed = try NetworkInterfaceCanonicalizer.canonicalize(
      Data("\(en0)\n\(utun.replacingOccurrences(of: "1380", with: "1400"))".utf8),
      window: window
    )

    #expect(first == reordered)
    #expect(first.inventory.itemCount == 2)
    #expect(first.utunCount == 1)
    #expect(first.utunTokens.count == 1)
    #expect(first.inventory != changed.inventory)
  }

  @Test func interfacesRejectDuplicateOrMalformedPreamble() {
    let window = NetworkCleanupCaptureWindow(keyData: Data(repeating: 8, count: 32))
    let duplicate = """
      en0: flags=1<UP> mtu 1500
      en0: flags=1<UP> mtu 1500
      """
    #expect(throws: NetworkCleanupCanonicalizationError.duplicateValue) {
      try NetworkInterfaceCanonicalizer.canonicalize(Data(duplicate.utf8), window: window)
    }
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try NetworkInterfaceCanonicalizer.canonicalize(
        Data("  status: active\n".utf8),
        window: window
      )
    }
    let nearMiss = """
      utunfoo: flags=1<UP> mtu 1500
        status: active
      """
    let parsed = try? NetworkInterfaceCanonicalizer.canonicalize(
      Data(nearMiss.utf8),
      window: window
    )
    #expect(parsed?.utunCount == 0)
  }

  @Test func interfaceTokensAreWindowScopedHMACs() throws {
    let fixture = Data("utun8: flags=1<UP> mtu 1380\n  status: active\n".utf8)
    let first = try NetworkInterfaceCanonicalizer.canonicalize(
      fixture,
      window: NetworkCleanupCaptureWindow(keyData: Data(repeating: 1, count: 32))
    )
    let second = try NetworkInterfaceCanonicalizer.canonicalize(
      fixture,
      window: NetworkCleanupCaptureWindow(keyData: Data(repeating: 2, count: 32))
    )
    #expect(first.inventory == second.inventory)
    #expect(first.utunTokens != second.utunTokens)
  }

  @Test func observedFingerprintRequiresLowercaseSHA256() {
    #expect(
      !NetworkCleanupFingerprint(
        state: .observed,
        itemCount: 1,
        sha256: String(repeating: "A", count: 64)
      ).isObserved
    )
    #expect(
      NetworkCleanupFingerprint(
        state: .observed,
        itemCount: 1,
        sha256: String(repeating: "a", count: 64)
      ).isObserved
    )
  }
}

private func dnsFixture(firstServer: String, secondServer: String) -> String {
  """
  DNS configuration

  resolver #1
    nameserver[0] : \(firstServer)
    if_index : 8 (en0)
    order : 200000

  resolver #2
    nameserver[0] : \(secondServer)
    if_index : 26 (utun8)
    order : 100000
  """
}
