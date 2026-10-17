import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct NativeTrialPortalBridgeTests {
  @Test func authenticatedXMLFeedsNativeRequestsWithPortalFamilyFour() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: """
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
        <NC_RESOURCE mapid="synthetic-map"><TUNNEL tunnel-name="Campus NC" status="1">
        <IKE family="4"><CLIENT id="synthetic-session"/><SERVER port="500"/>
        <ISAKMP-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="aes128" hash="sha256" life-time="3600"/></TRANSFORMS></PROPOSAL></ISAKMP-SA>
        <IPSEC-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="aes128" hash="sha256" life-time="1800"/></TRANSFORMS></PROPOSAL></IPSEC-SA>
        <PSK key="synthetic-psk"/><EXTENSIONS><PRIVATE-IP addr="192.0.2.9"/>
        <SECURED-ROUTES name="direct"><ROUTE addr="198.51.100.0/24"/></SECURED-ROUTES></EXTENSIONS>
        </IKE></TUNNEL></NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """)
    defer { fixture.erase() }
    let configuration = try PowerVPNTargetsConfiguration.decode(
      Data(
        """
        {"portalOrigin":"https://192.0.2.1:4443","targets":{"synthetic":{"host":"198.51.100.7","user":"synthetic","resource":"Campus NC"}}}
        """.utf8))
    var called = false
    try NativeTrialPortalBridge.withRequests(
      snapshot: fixture.snapshot, target: configuration.target(named: "synthetic"),
      name: "synthetic"
    ) { shared, connection in
      called = true
      let sharedBytes = try VICIMessageCodec.encode(shared)
      let connectionBytes = try VICIMessageCodec.encode(connection)
      #expect(sharedBytes.range(of: Data("synthetic-psk".utf8)) != nil)
      // NC resources use remote TS 0.0.0.0/0, as the vendor helper does; the
      // resource CIDR travels in ADDRULE instead.
      #expect(connectionBytes.range(of: Data("0.0.0.0/0".utf8)) != nil)
      #expect(connectionBytes.range(of: Data("198.51.100.7/32".utf8)) == nil)
    }
    #expect(called)
  }
}
