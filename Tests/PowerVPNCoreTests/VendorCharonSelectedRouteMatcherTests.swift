import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonSelectedRouteMatcherTests {
  @Test func selectedRoutesNormalizeHostFormAndBSDAbbreviatedDestination() throws {
    let snapshot = try selectedSnapshot(
      family: 4,
      routes: [("10.1.2.3", 24), ("0.0.0.0", 0), ("10.1.2.99", 24)]
    )
    let matcher = try snapshot.makeSelectedRouteMatcher(
      requiredTargetIPv4: ipv4(10, 1, 2, 200)
    )

    #expect(matcher.selectedRouteCount == 2)
    #expect(try matchedCount(matcher, destination: "10.1.2/24") == 1)
    #expect(try matchedCount(matcher, destination: "10.1.2.77/24") == 1)
    #expect(try matchedCount(matcher, destination: "default") == 1)
    #expect(try matchedCount(matcher, destination: "10.1.3/24") == 0)
  }

  @Test func routeCanonicalizerReportsOnlyMatchedCount() throws {
    let matcher = try selectedSnapshot(
      family: 4,
      routes: [("10.1.2.3", 24), ("203.0.113.9", 32)]
    ).makeSelectedRouteMatcher(requiredTargetIPv4: ipv4(203, 0, 113, 9))
    let table = """
      Routing tables
      Internet:
      Destination Gateway Flags Netif Expire
      default 192.0.2.1 UGScg en0
      10.1.2/24 link#9 UGScI utun9
      203.0.113.9 link#9 UH utun9
      """
    let result = try NetworkRouteCanonicalizer.canonicalize(
      Data(table.utf8),
      family: .inet,
      selectedRoutes: matcher
    )
    #expect(result.selectedRouteMatchCount == 2)
    #expect(result.selectedRouteTokens.count == 2)
  }

  @Test func sameDestinationWithDifferentBindingProducesDifferentToken() throws {
    let matcher = try selectedSnapshot(
      family: 4,
      routes: [("10.1.2.3", 24)]
    ).makeSelectedRouteMatcher(requiredTargetIPv4: ipv4(10, 1, 2, 9))
    let before = try canonicalRoute(
      matcher,
      rows: ["default 192.0.2.1 UGScg en0", "10.1.2/24 link#4 UGScI en0"]
    )
    let active = try canonicalRoute(
      matcher,
      rows: ["default 192.0.2.1 UGScg en0", "10.1.2/24 link#9 UGScI utun9"]
    )
    let flagsChanged = try canonicalRoute(
      matcher,
      rows: ["default 192.0.2.1 UGScg en0", "10.1.2/24 link#4 UGS en0"]
    )
    let hostForm = try canonicalRoute(
      matcher,
      rows: ["default 192.0.2.1 UGScg en0", "10.1.2.77/24 link#4 UGScI en0"]
    )

    #expect(before.selectedRouteMatchCount == 1)
    #expect(active.selectedRouteMatchCount == 1)
    #expect(before.selectedRouteTokens.isDisjoint(with: active.selectedRouteTokens))
    #expect(active.selectedRouteTokens.subtracting(before.selectedRouteTokens).count == 1)
    #expect(before.selectedRouteTokens == flagsChanged.selectedRouteTokens)
    #expect(before.selectedRouteTokens == hostForm.selectedRouteTokens)
  }

  @Test func unsupportedFamilyAndInvalidMaterialFailWithoutEcho() throws {
    let ipv6 = try selectedSnapshot(family: 6, routes: [("10.0.0.1", 32)])
    #expect(throws: VendorCharonSelectedRouteMatcherError.unsupportedFamily) {
      try ipv6.makeSelectedRouteMatcher(requiredTargetIPv4: ipv4(10, 0, 0, 1))
    }

    let invalid = try selectedSnapshot(family: 4, routes: [("sensitive.invalid", 32)])
    do {
      _ = try invalid.makeSelectedRouteMatcher(requiredTargetIPv4: ipv4(10, 0, 0, 1))
      Issue.record("invalid selected route unexpectedly accepted")
    } catch {
      #expect(String(describing: error) == "invalidNetwork")
      #expect(!String(describing: error).contains("sensitive"))
    }
  }

  @Test func targetCoverageAcceptsDefaultExactAndBroaderButRejectsMiss() throws {
    let target = ipv4(11, 11, 30, 21)
    let defaultRoute = try selectedSnapshot(family: 4, routes: [("0.0.0.0", 0)])
    let exact = try selectedSnapshot(family: 4, routes: [("11.11.30.21", 32)])
    let broader = try selectedSnapshot(family: 4, routes: [("11.11.0.7", 16)])
    let miss = try selectedSnapshot(family: 4, routes: [("11.12.0.0", 16)])

    #expect(
      try defaultRoute.makeSelectedRouteMatcher(requiredTargetIPv4: target).selectedRouteCount == 1)
    #expect(try exact.makeSelectedRouteMatcher(requiredTargetIPv4: target).selectedRouteCount == 1)
    #expect(
      try broader.makeSelectedRouteMatcher(requiredTargetIPv4: target).selectedRouteCount == 1)
    #expect(throws: VendorCharonSelectedRouteMatcherError.requiredTargetNotCovered) {
      try miss.makeSelectedRouteMatcher(requiredTargetIPv4: target)
    }
  }

  @Test func matcherBindsTheExactSnapshotLineageAndRequiredTarget() throws {
    let target = ipv4(11, 11, 30, 21)
    let otherTarget = ipv4(11, 11, 30, 52)
    let first = try selectedSnapshot(family: 4, routes: [("11.11.30.0", 24)])
    let second = try selectedSnapshot(family: 4, routes: [("11.11.30.0", 24)])
    let matcher = try first.makeSelectedRouteMatcher(requiredTargetIPv4: target)

    #expect(first.isBound(to: matcher, requiredTargetIPv4: target))
    #expect(!second.isBound(to: matcher, requiredTargetIPv4: target))
    #expect(!first.isBound(to: matcher, requiredTargetIPv4: otherTarget))
  }
}

private func matchedCount(
  _ matcher: VendorCharonSelectedRouteMatcher,
  destination: String
) throws -> Int {
  try canonicalRoute(
    matcher,
    rows: ["\(destination) link#9 UGScI utun9"]
  ).selectedRouteMatchCount
}

private func canonicalRoute(
  _ matcher: VendorCharonSelectedRouteMatcher,
  rows: [String]
) throws -> NetworkCleanupRouteSnapshot {
  let table =
    "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n"
    + rows.joined(separator: "\n") + "\n"
  return try NetworkRouteCanonicalizer.canonicalize(
    Data(table.utf8),
    family: .inet,
    selectedRoutes: matcher
  )
}

private func ipv4(_ a: UInt32, _ b: UInt32, _ c: UInt32, _ d: UInt32) -> UInt32 {
  (a << 24) | (b << 16) | (c << 8) | d
}

private func selectedSnapshot(
  family: Int32,
  routes: [(String, Int32)]
) throws -> VendorCharonStartSnapshot {
  let values = SelectedRouteTestValues()
  let candidates = routes.map { network, prefix in
    VendorCharonStartRouteCandidate(
      network: values.text(network),
      prefix: values.prefix(prefix)
    )
  }
  let candidate = VendorCharonStartCandidate(
    lineage: values.lineage,
    common: VendorCharonStartCommonCandidate(
      sessionID: values.text("session"),
      gateway: values.text("gateway"),
      ikePort: values.integer(500),
      majorVersion: values.integer(2),
      ike: values.text("ike"),
      esp: values.text("esp"),
      psk: values.text("psk"),
      ikeLifetime: values.integer(3_600),
      ipsecLifetime: values.integer(3_600)
    ),
    tunnels: [
      VendorCharonStartTunnelCandidate(
        authority: values.integer(1),
        status: values.integer(1),
        tunnelName: values.text("tunnel"),
        family: values.integer(family),
        resourceFlag: values.integer(1),
        name: values.text("resource"),
        routes: candidates,
        mapID: values.text("map")
      )
    ]
  )
  return try #require(VendorCharonStartValidator.validate(candidate).snapshot)
}

private struct SelectedRouteTestValues {
  let lineage = VendorCharonStartLineage()

  func text(_ value: String) -> VendorCharonStartTextValue {
    VendorCharonStartTextValue(
      value: SelectedRouteTextMaterial(value),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  func integer(_ value: Int32) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: value,
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  func prefix(_ value: Int32) -> VendorCharonStartPrefixValue {
    VendorCharonStartPrefixValue(
      value: .integer(value),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }
}

private struct SelectedRouteTextMaterial: VendorCharonStartTextMaterial {
  private let bytes: [UInt8]
  let byteCount: Int

  init(_ value: String) {
    bytes = Array(value.utf8)
    byteCount = bytes.count
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }
}
