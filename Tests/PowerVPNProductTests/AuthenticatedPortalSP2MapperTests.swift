import PowerVPNCore
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct AuthenticatedPortalSP2MapperTests {
  @Test func exactAttributeFieldsAndDirectCIDRBecomeAvailable() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeSP2XML)
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    let available: [VendorCharonStartField] = [
      .sessionID, .vip, .ikePort, .majorVersion, .ike, .esp, .psk,
      .ikeLifetime, .ipsecLifetime, .authority, .status, .tunnelName,
      .family, .resourceFlag, .name, .routes, .mapID, .negotiateMode,
      .routeNetwork, .routePrefix,
    ]
    for field in available {
      #expect(availability(of: field, in: candidate) == .available)
    }
    #expect(availability(of: .gateway, in: candidate) == .missingRequired)
    #expect(sources(of: .majorVersion, in: candidate) == [.authenticatedPortalMetadata])
    #expect(sources(of: .resourceFlag, in: candidate) == [.generatedConstant])
    #expect(sources(of: .routes, in: candidate) == [.generatedContainer])
    #expect(sources(of: .routeNetwork, in: candidate) == [.authenticatedPortalResource])
  }

  @Test func helperChildTextShapeDoesNotMasqueradeAsAttribute() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: """
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST><NC_RESOURCE>
          <TUNNEL tunnel-name="Campus NC"><IKE><CLIENT>
            <id>child-only-session</id>
          </CLIENT></IKE></TUNNEL>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """)
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    #expect(availability(of: .sessionID, in: candidate) == .missingRequired)
  }

  @Test func proposalLiteralNullDefaultsButChildTextDoesNot() throws {
    let literal = try authenticatedSnapshot(
      resourceXML: proposalXML(
        transform: #"<TRANSFORM enc="null" hash="null" life-time="3600"/>"#
      ))
    defer { literal.erase() }
    let literalCandidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(literal.snapshot).first
    )
    #expect(availability(of: .ike, in: literalCandidate) == .available)

    let child = try authenticatedSnapshot(
      resourceXML: proposalXML(
        transform:
          "<TRANSFORM><enc>null</enc><hash>null</hash><life-time>3600</life-time></TRANSFORM>"
      ))
    defer { child.erase() }
    let childCandidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(child.snapshot).first
    )
    #expect(availability(of: .ike, in: childCandidate) == .missingRequired)
    #expect(availability(of: .ikeLifetime, in: childCandidate) == .missingRequired)
  }

  @Test func emptyRouteShapeIsGeneratedAndApplicable() throws {
    let fixture = try authenticatedSnapshot(resourceXML: tunnelXML(extensions: ""))
    defer { fixture.erase() }
    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )

    #expect(availability(of: .resourceFlag, in: candidate) == .available)
    #expect(sources(of: .resourceFlag, in: candidate) == [.generatedConstant])
    #expect(availability(of: .name, in: candidate) == .available)
    #expect(sources(of: .name, in: candidate) == [.generatedConstant])
    #expect(availability(of: .routes, in: candidate) == .available)
    #expect(availability(of: .routeNetwork, in: candidate) == .notApplicable)
    #expect(availability(of: .routePrefix, in: candidate) == .notApplicable)
  }

  @Test func nonNetworkAlignedCIDRPreservesVendorNetAndPrefix() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeSP2XML)
    defer { fixture.erase() }

    try fixture.snapshot.withResourceTree { list in
      let resource = try #require(list.childElements.first { $0.name == "NC_RESOURCE" })
      let tunnel = try #require(resource.childElements.first { $0.name == "TUNNEL" })
      let ike = try #require(tunnel.childElements.first { $0.name == "IKE" })
      let extensions = try #require(ike.childElements.first { $0.name == "EXTENSIONS" })
      let mapping = try AuthenticatedPortalSP2RouteMapper.map(
        extensions: extensions,
        lineage: VendorCharonStartLineage()
      )
      let route = try #require(mapping.routes?.first)
      let network = try #require(route.network)
      let networkText = try network.value.withUnsafeUTF8Bytes {
        String(decoding: $0, as: UTF8.self)
      }
      #expect(networkText == "10.1.2.3")
      let prefix = try #require(route.prefix)
      guard case .integer(let value) = prefix.value else {
        Issue.record("direct CIDR prefix must stay integer")
        return
      }
      #expect(value == 24)
    }
  }

  @Test func unsupportedHyphenRangeLeavesWholeRoutesMissing() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: tunnelXML(
        extensions: """
          <SECURED-ROUTES name="range"><RANGE addr="10.0.0.1-10.0.0.9"/></SECURED-ROUTES>
          """))
    defer { fixture.erase() }
    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )

    #expect(availability(of: .resourceFlag, in: candidate) == .available)
    #expect(sources(of: .resourceFlag, in: candidate) == [.authenticatedPortalResource])
    #expect(availability(of: .routes, in: candidate) == .missingRequired)
  }
}

private let completeSP2XML = tunnelXML(
  extensions: """
    <PRIVATE-IP addr="10.10.10.4"/>
    <SECURED-ROUTES name="direct"><ROUTE addr="10.1.2.3/24"/></SECURED-ROUTES>
    """,
  ikeBody: """
    <CLIENT id="helper-session-material"/><SERVER port="500"/>
    <ISAKMP-SA><PROPOSAL><TRANSFORMS>
      <TRANSFORM enc="null" hash="null" life-time="3600"/>
    </TRANSFORMS></PROPOSAL></ISAKMP-SA>
    <IPSEC-SA><PROPOSAL><TRANSFORMS>
      <TRANSFORM enc="aes256" hash="sha256" life-time="1800"/>
    </TRANSFORMS></PROPOSAL></IPSEC-SA><PSK key="psk-material"/>
    """)

private func proposalXML(transform: String) -> String {
  tunnelXML(
    extensions: "",
    ikeBody: """
      <CLIENT id="helper-session"/><ISAKMP-SA><PROPOSAL><TRANSFORMS>
        \(transform)
      </TRANSFORMS></PROPOSAL></ISAKMP-SA>
      """)
}

private func tunnelXML(extensions: String, ikeBody: String = "<CLIENT id=\"session\"/>")
  -> String
{
  """
  <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
    <NC_RESOURCE status="1" mapid="resource-map"><TUNNEL tunnel-name="Campus NC"
      authority="7" status="9" mapid="tunnel-map" negotiate-mode="3">
      <IKE family="4">\(ikeBody)<EXTENSIONS>\(extensions)</EXTENSIONS></IKE>
    </TUNNEL></NC_RESOURCE>
  </RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """
}
