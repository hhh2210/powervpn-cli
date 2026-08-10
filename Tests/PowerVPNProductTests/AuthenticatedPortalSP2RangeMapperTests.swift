import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct AuthenticatedPortalSP2RangeMapperTests {
  @Test func wholeIPv4SpaceBecomesOneDefaultRoute() throws {
    #expect(
      try mappedRange("0.0.0.0-255.255.255.255") == [
        RouteExpectation(network: "0.0.0.0", prefix: 0)
      ]
    )
  }

  @Test func irregularRangeUsesAscendingMinimalCIDRCover() throws {
    #expect(
      try mappedRange("10.0.0.1-10.0.0.6") == [
        RouteExpectation(network: "10.0.0.1", prefix: 32),
        RouteExpectation(network: "10.0.0.2", prefix: 31),
        RouteExpectation(network: "10.0.0.4", prefix: 31),
        RouteExpectation(network: "10.0.0.6", prefix: 32),
      ]
    )
  }

  @Test(
    arguments: [
      RangeExpectation(
        input: "10.0.0.0-10.0.0.255",
        routes: [RouteExpectation(network: "10.0.0.0", prefix: 24)]
      ),
      RangeExpectation(
        input: "127.255.255.255-128.0.0.0",
        routes: [
          RouteExpectation(network: "127.255.255.255", prefix: 32),
          RouteExpectation(network: "128.0.0.0", prefix: 32),
        ]
      ),
      RangeExpectation(
        input: "255.255.255.254-255.255.255.255",
        routes: [RouteExpectation(network: "255.255.255.254", prefix: 31)]
      ),
      RangeExpectation(
        input: "0.0.0.0-0.0.0.0",
        routes: [RouteExpectation(network: "0.0.0.0", prefix: 32)]
      ),
    ]
  )
  func hostOrderBoundariesRemainExact(_ expectation: RangeExpectation) throws {
    #expect(try mappedRange(expectation.input) == expectation.routes)
  }

  @Test(
    arguments: [
      "10.0.0.2-10.0.0.1",
      "10.0.0.1-",
      "-10.0.0.1",
      "10.0.0.1-10.0.0.256",
      "10.0.0.01-10.0.0.2",
      "10.0.0.1-10.0.0.2-10.0.0.3",
      "10.0.0.1/24-10.0.0.2",
    ]
  )
  func reversedAndMalformedRangesFailClosed(_ input: String) throws {
    #expect(try mappedRange(input) == nil)
  }

  @Test func oneInvalidRangeMakesTheWholeTunnelRoutesMissing() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: rangeDocument(
        resources: rangeResource(
          name: "one-tunnel",
          rangeElements: """
            <RANGE addr="10.0.0.0-10.0.0.255"/>
            <RANGE addr="10.0.1.2-10.0.1.1"/>
            """
        )
      )
    )
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    #expect(availability(of: .routes, in: candidate) == .missingRequired)
    #expect(availability(of: .routeNetwork, in: candidate) == .notApplicable)
  }

  @Test func siblingResourcesNeverUnionValidAndInvalidRanges() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: rangeDocument(
        resources: """
          \(rangeResource(
            name: "invalid-range",
            rangeElements: #"<RANGE addr="10.0.0.2-10.0.0.1"/>"#
          ))
          \(rangeResource(
            name: "valid-range",
            rangeElements: #"<RANGE addr="10.0.1.0-10.0.1.255"/>"#
          ))
          """
      )
    )
    defer { fixture.erase() }

    let candidates = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    #expect(candidates.count == 2)
    #expect(availability(of: .routes, in: candidates[0]) == .missingRequired)
    #expect(availability(of: .routes, in: candidates[1]) == .available)
    #expect(availability(of: .routeNetwork, in: candidates[1]) == .available)
  }

  @Test func rangeEndpointsAndDerivedNetworksStayOutOfProductJSON() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: rangeDocument(
        resources: rangeResource(
          name: "value-free-range",
          rangeElements: #"<RANGE addr="10.7.0.1-10.7.0.6"/>"#
        )
      )
    )
    defer { fixture.erase() }

    let report = try ProductReadinessRuntime(
      observer: MapperProductObservation()
    ).snapshotDryRun(from: fixture.snapshot)
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
    #expect(!json.contains("10.7.0.1"))
    #expect(!json.contains("10.7.0.2"))
    #expect(!json.contains("10.7.0.6"))
    #expect(!json.contains("/"))
  }
}

struct RouteExpectation: Equatable, Sendable {
  let network: String
  let prefix: Int32
}

struct RangeExpectation: Sendable {
  let input: String
  let routes: [RouteExpectation]
}

private func mappedRange(_ input: String) throws -> [RouteExpectation]? {
  let fixture = try authenticatedSnapshot(
    resourceXML: rangeDocument(
      resources: rangeResource(
        name: "range-test",
        rangeElements: "<RANGE addr=\"\(input)\"/>"
      )
    )
  )
  defer { fixture.erase() }

  return try fixture.snapshot.withResourceTree { list in
    let resource = try #require(list.childElements.first { $0.name == "NC_RESOURCE" })
    let tunnel = try #require(resource.childElements.first { $0.name == "TUNNEL" })
    let ike = try #require(tunnel.childElements.first { $0.name == "IKE" })
    let extensions = try #require(ike.childElements.first { $0.name == "EXTENSIONS" })
    let mapping = try AuthenticatedPortalSP2RouteMapper.map(
      extensions: extensions,
      lineage: VendorCharonStartLineage()
    )
    return try mapping.routes?.map { route in
      let network = try #require(route.network)
      let text = try network.value.withUnsafeUTF8Bytes {
        String(decoding: $0, as: UTF8.self)
      }
      let prefix = try #require(route.prefix)
      guard case .integer(let value) = prefix.value else {
        throw RangeTestError.nonIntegerPrefix
      }
      return RouteExpectation(network: text, prefix: value)
    }
  }
}

private func rangeDocument(resources: String) -> String {
  """
  <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
    \(resources)
  </RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """
}

private func rangeResource(name: String, rangeElements: String) -> String {
  """
  <NC_RESOURCE status="1" mapid="map-\(name)">
    <TUNNEL tunnel-name="\(name)"><IKE><CLIENT id="session-\(name)"/>
      <EXTENSIONS><SECURED-ROUTES name="routes-\(name)">
        \(rangeElements)
      </SECURED-ROUTES></EXTENSIONS>
    </IKE></TUNNEL>
  </NC_RESOURCE>
  """
}

private enum RangeTestError: Error {
  case nonIntegerPrefix
}
