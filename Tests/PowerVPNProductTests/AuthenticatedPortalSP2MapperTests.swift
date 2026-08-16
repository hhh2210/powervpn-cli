import PowerVPNCore
import Testing
@preconcurrency import XPC

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
      .sessionID, .vip, .gateway, .ikePort, .majorVersion, .ike, .esp, .psk,
      .ikeLifetime, .ipsecLifetime, .authority, .status, .tunnelName,
      .family, .resourceFlag, .name, .routes, .mapID, .negotiateMode,
      .routeNetwork, .routePrefix,
    ]
    for field in available {
      #expect(availability(of: field, in: candidate) == .available)
    }
    #expect(candidate.snapshotComplete)
    #expect(candidate.firstMissingField == nil)
    #expect(sources(of: .gateway, in: candidate) == [.authenticatedPortalOrigin])
    #expect(sources(of: .majorVersion, in: candidate) == [.authenticatedPortalMetadata])
    #expect(sources(of: .resourceFlag, in: candidate) == [.generatedConstant])
    #expect(sources(of: .routes, in: candidate) == [.generatedContainer])
    #expect(sources(of: .routeNetwork, in: candidate) == [.authenticatedPortalResource])
  }

  @Test func helperChildTextShapeDoesNotMasqueradeAsAttribute() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: """
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
          <NC_RESOURCE status="1"><TUNNEL tunnel-name="Campus NC"><IKE><CLIENT>
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

  @Test func supportedHyphenRangeProducesMaterializedRoutes() throws {
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
    #expect(availability(of: .routes, in: candidate) == .available)
    #expect(availability(of: .routeNetwork, in: candidate) == .available)
    #expect(availability(of: .routePrefix, in: candidate) == .available)
  }

  /// Empty `vip` is legal official input: the charon daemon `_start_connection`
  /// reader guards it with `[NSString length] != 0` before `strcpy`
  /// (`0x1001aa676`–`0x1001aa6f7`; sp2-startsnapshot dossier §4, 2026-08-11),
  /// so a present-but-empty attribute must survive the whole catalog→snapshot
  /// chain instead of rejecting the resource.
  @Test func emptyVipAttributeProducesAnAvailableCompleteCandidate() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: tunnelXML(
        extensions: """
          <PRIVATE-IP addr=""/>
          <SECURED-ROUTES name="direct"><ROUTE addr="10.1.2.3/24"/></SECURED-ROUTES>
          """,
        ikeBody: completeSP2IKEBody
      ))
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    #expect(availability(of: .vip, in: candidate) == .available)
    #expect(candidate.snapshotComplete)
    #expect(candidate.firstMissingField == nil)
  }

  /// A missing `addr` attribute (or a child-shaped `addr`) never fabricates
  /// vip material: only the attribute shape is a helper scalar, and absence
  /// stays the daemon-legal optional-absence, never an invented value.
  @Test func missingOrChildShapedAddrAttributeNeverFabricatesVipMaterial() throws {
    for extensions in [
      "<PRIVATE-IP/>",
      "<PRIVATE-IP><addr>10.10.10.4</addr></PRIVATE-IP>",
    ] {
      let fixture = try authenticatedSnapshot(
        resourceXML: tunnelXML(extensions: extensions, ikeBody: completeSP2IKEBody))
      defer { fixture.erase() }

      let candidate = try #require(
        AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
      )
      #expect(availability(of: .vip, in: candidate) == .absentOptional)
    }
  }

  /// Ground-truth shape: PRIVATE-IP is a DIRECT child of NC_RESOURCE
  /// (intergration-structure-report.txt:77-81), not under IKE→EXTENSIONS.
  /// The official client resolves vip from this resource-child shape via its
  /// portal `property["vip"]` fallback (`0x1000aa70c`–`0x1000aa894`,
  /// `0x1000687f3`–`0x1000688f8`); the mapper mirrors the effective chain.
  @Test func resourceChildPrivateIPProvidesVipWhenIKEChaseMisses() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: tunnelXML(
        extensions:
          "<SECURED-ROUTES name=\"direct\"><ROUTE addr=\"10.1.2.3/24\"/></SECURED-ROUTES>",
        ikeBody: completeSP2IKEBody,
        resourceChildren: "<PRIVATE-IP addr=\"10.10.10.4\"/>"
      ))
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    #expect(availability(of: .vip, in: candidate) == .available)
    #expect(sources(of: .vip, in: candidate) == [.authenticatedPortalResource])
    #expect(try encodedVIP(in: fixture.snapshot, handle: candidate.summary.handle) == "10.10.10.4")
    #expect(candidate.snapshotComplete)
  }

  /// When both official sources carry an address, the direct
  /// IKE→EXTENSIONS chase wins over the portal-property fallback.
  @Test func extensionPrivateIPWinsWhenBothPathsHaveAddresses() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: tunnelXML(
        extensions: "<PRIVATE-IP addr=\"10.10.10.4\"/>",
        ikeBody: completeSP2IKEBody,
        resourceChildren: "<PRIVATE-IP addr=\"10.10.10.5\"/>"
      ))
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    #expect(try encodedVIP(in: fixture.snapshot, handle: candidate.summary.handle) == "10.10.10.4")
    #expect(candidate.snapshotComplete)
  }

  /// A present extension PRIVATE-IP without `addr` leaves the chase nil, so
  /// the official portal-property value remains the fallback.
  @Test func extensionPrivateIPWithoutAddrFallsBackToResourceChild() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: tunnelXML(
        extensions: "<PRIVATE-IP/>",
        ikeBody: completeSP2IKEBody,
        resourceChildren: "<PRIVATE-IP addr=\"10.10.10.5\"/>"
      ))
    defer { fixture.erase() }

    let candidate = try #require(
      AuthenticatedPortalSnapshotMapper.map(fixture.snapshot).first
    )
    #expect(try encodedVIP(in: fixture.snapshot, handle: candidate.summary.handle) == "10.10.10.5")
    #expect(candidate.snapshotComplete)
  }
}

private let completeSP2XML = tunnelXML(
  extensions: completeSP2Extensions, ikeBody: completeSP2IKEBody)

private let completeSP2Extensions = """
  <PRIVATE-IP addr="10.10.10.4"/>
  <SECURED-ROUTES name="direct"><ROUTE addr="10.1.2.3/24"/></SECURED-ROUTES>
  """

private let completeSP2IKEBody = """
  <CLIENT id="helper-session-material"/><SERVER port="500"/>
  <ISAKMP-SA><PROPOSAL><TRANSFORMS>
    <TRANSFORM enc="null" hash="null" life-time="3600"/>
  </TRANSFORMS></PROPOSAL></ISAKMP-SA>
  <IPSEC-SA><PROPOSAL><TRANSFORMS>
    <TRANSFORM enc="aes256" hash="sha256" life-time="1800"/>
  </TRANSFORMS></PROPOSAL></IPSEC-SA><PSK key="psk-material"/>
  """

private func proposalXML(transform: String) -> String {
  tunnelXML(
    extensions: "",
    ikeBody: """
      <CLIENT id="helper-session"/><ISAKMP-SA><PROPOSAL><TRANSFORMS>
        \(transform)
      </TRANSFORMS></PROPOSAL></ISAKMP-SA><PSK key="psk-material"/>
      """)
}

private func tunnelXML(
  extensions: String,
  ikeBody: String = "<CLIENT id=\"session\"/>",
  resourceChildren: String = ""
) -> String {
  """
  <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
    <NC_RESOURCE status="1" mapid="resource-map">\(resourceChildren)<TUNNEL
      tunnel-name="Campus NC" authority="7" status="9" mapid="tunnel-map"
      negotiate-mode="3">
      <IKE family="4">\(ikeBody)<EXTENSIONS>\(extensions)</EXTENSIONS></IKE>
    </TUNNEL></NC_RESOURCE>
  </RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """
}

private func encodedVIP(
  in snapshot: AuthenticatedPortalSnapshot,
  handle: String
) throws -> String {
  var encodedVIP: String?
  try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
    snapshot,
    handle: handle
  ) { startSnapshot in
    try startSnapshot.withEncodedStartMessage { root in
      let common = try #require(xpc_dictionary_get_value(root, "common"))
      let vip = try #require(xpc_dictionary_get_string(common, "vip"))
      encodedVIP = String(cString: vip)
    }
  }
  return try #require(encodedVIP)
}
