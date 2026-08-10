import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupRouteTests {
  @Test func structuralAndPersistentProfilesMatchLockedShellSemantics() throws {
    let base = routeFixture(
      rows: [
        "default 192.0.2.1 UGScg en0",
        "192.0.2.0/24 link#4 UCS en0",
        "198.51.100.10 192.0.2.1 UHWI en0 9",
        "203.0.113.0/24 link#9 UGScI utun9",
      ])
    let expireChanged = base.replacingOccurrences(of: "en0 9", with: "en0 8")
    let clonedAdded = base + "198.51.100.11 192.0.2.1 UHWI en0\n"
    let persistentChanged = base.replacingOccurrences(
      of: "203.0.113.0/24 link#9",
      with: "203.0.113.0/24 192.0.2.1"
    )

    let a = try canonical(base)
    let b = try canonical(expireChanged)
    let c = try canonical(clonedAdded)
    let d = try canonical(persistentChanged)
    #expect(a.structural == b.structural)
    #expect(a.persistent == b.persistent)
    #expect(a.structural != c.structural)
    #expect(a.persistent == c.persistent)
    #expect(a.persistent != d.persistent)
    #expect(a.structural.itemCount == 4)
    #expect(a.persistent.itemCount == 3)
  }

  @Test func routeOrderingIsCanonicalAndDuplicatesRemainVisible() throws {
    let rows = [
      "default 192.0.2.1 UGScg en0",
      "192.0.2.0/24 link#4 UCS en0",
      "203.0.113.0/24 link#9 UGScI utun9",
    ]
    let a = try canonical(routeFixture(rows: rows))
    let b = try canonical(routeFixture(rows: rows.reversed()))
    let duplicate = try canonical(routeFixture(rows: rows + [rows[0]]))
    #expect(a == b)
    #expect(a.persistent != duplicate.persistent)
    #expect(duplicate.persistent.itemCount == 4)
  }

  @Test func ipv6UsesIndependentDomainAndPersistentProjection() throws {
    let text = """
      Routing tables

      Internet6:
      Destination Gateway Flags Netif Expire
      default fe80::1%en0 UGcg en0
      2001:db8::/32 link#9 UCS utun9
      fe80::1 link#1 UHLWI lo0 5
      """
    let snapshot = try NetworkRouteCanonicalizer.canonicalize(
      Data(text.utf8),
      family: .inet6
    )
    #expect(snapshot.structural.itemCount == 3)
    #expect(snapshot.persistent.itemCount == 2)
    #expect(snapshot.selectedRouteMatchCount == 0)
  }

  @Test func malformedTablesFailClosed() {
    for text in [
      "Internet:\nDestination Gateway Flags Netif Expire\ndefault 1.1.1.1 UG en0\n",
      "Routing tables\nInternet6:\nDestination Gateway Flags Netif Expire\n",
      routeFixture(rows: ["default 192.0.2.1 UZ en0"]),
      routeFixture(rows: ["default 192.0.2.1 UGScg 9tun"]),
      routeFixture(rows: ["default 192.0.2.1 UGScg en0 0"]),
      routeFixture(rows: ["default 192.0.2.1 UGScg"]),
    ] {
      #expect(throws: (any Error).self) {
        try NetworkRouteCanonicalizer.canonicalize(Data(text.utf8), family: .inet)
      }
    }
  }
}

private func canonical(_ text: String) throws -> NetworkCleanupRouteSnapshot {
  try NetworkRouteCanonicalizer.canonicalize(Data(text.utf8), family: .inet)
}

private func routeFixture<S: Sequence>(rows: S) -> String where S.Element == String {
  """
  Routing tables

  Internet:
  Destination Gateway Flags Netif Expire
  \(rows.joined(separator: "\n"))
  """ + "\n"
}
