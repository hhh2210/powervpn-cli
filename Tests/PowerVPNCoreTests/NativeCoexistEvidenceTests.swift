import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeCoexistEvidenceTests {
  private let baseline: Set<String> = ["utun6", "utun9"]
  private let target = "198.51.100.52"
  private var route: String {
    "route to: \(target)\ndestination: \(target)\ngateway: 192.0.2.1\ninterface: utun10\nflags: <UP,GATEWAY,HOST,DONE,STATIC>\n"
  }

  @Test func frozenScopeRejectsRetargetedMutableConfiguration() throws {
    try NativeCoexistEvidence.requireFrozenScope(
      targetHost: "11.11.37.52", portalHost: "166.111.143.19")
    for host in ["11.11.30.21", "198.51.100.52", "11.11.37.052", "thu52", ""] {
      #expect(throws: NativeCoexistFailure.self) {
        try NativeCoexistEvidence.requireFrozenScope(targetHost: host, portalHost: "166.111.143.19")
      }
    }
    for origin in ["192.0.2.1", "166.111.143.019", "vpn.example.test", "", nil] {
      #expect(throws: NativeCoexistFailure.self) {
        try NativeCoexistEvidence.requireFrozenScope(targetHost: "11.11.37.52", portalHost: origin)
      }
    }
  }

  @Test func gatewayMustMatchFrozenValueEvenWhenMutableOriginAgrees() throws {
    try NativeCoexistEvidence.requireFrozenGateway(
      "166.111.143.19", expectedOriginHost: "166.111.143.19")
    for gateway in ["192.0.2.1", "166.111.143.019", "vpn.example.test", ""] {
      #expect(throws: NativeCoexistFailure.self) {
        try NativeCoexistEvidence.requireFrozenGateway(gateway, expectedOriginHost: gateway)
      }
    }
    #expect(throws: NativeCoexistFailure.self) {
      try NativeCoexistEvidence.requireFrozenGateway(
        "166.111.143.19", expectedOriginHost: "192.0.2.1")
    }
  }

  @Test func requiresExactHostOnANewUtun() {
    #expect(
      NativeCoexistEvidence.routeIsNewUtun(Data(route.utf8), target: target, baseline: baseline))
    for change in [
      route.replacingOccurrences(of: "utun10", with: "utun9"),
      route.replacingOccurrences(of: "utun10", with: "utun6"),
      route.replacingOccurrences(of: "utun10", with: "en0"),
      route.replacingOccurrences(of: "utun10", with: "utunx"),
      route.replacingOccurrences(of: "destination: \(target)", with: "destination: default"),
      route.replacingOccurrences(of: "HOST,", with: ""),
      route.replacingOccurrences(of: "UP,", with: ""),
      route + "mask: 255.255.255.0\n",
      route + "interface: utun11\n",
    ] {
      #expect(
        !NativeCoexistEvidence.routeIsNewUtun(Data(change.utf8), target: target, baseline: baseline)
      )
    }
  }

  @Test func newInterfaceMustAlsoBelongToRootNativeLedgerWithCurrentIndex() throws {
    let ledger = try NativeCoexistEvidence.ownedInterfaces(
      from: Data("utun10 31\nutun11 32\n".utf8))
    #expect(
      NativeCoexistEvidence.ownedRouteMatches(
        interface: "utun11", ledger: ledger, currentInterfaceIndex: 32))
    #expect(
      !NativeCoexistEvidence.ownedRouteMatches(
        interface: "utun12", ledger: ledger, currentInterfaceIndex: 33))
    #expect(
      !NativeCoexistEvidence.ownedRouteMatches(
        interface: "utun11", ledger: ledger, currentInterfaceIndex: 99))
    #expect(
      !NativeCoexistEvidence.ownedRouteMatches(
        interface: "utun11", ledger: ledger, currentInterfaceIndex: 0))
    for text in [
      "utun10 31\nutun10 31", "utun10 31\nutun11 31", "utun10 0", "utun10 031", "utun10", "en0 4",
    ] {
      #expect(throws: NativeCoexistFailure.self) {
        try NativeCoexistEvidence.ownedInterfaces(from: Data(text.utf8))
      }
    }
  }
}
