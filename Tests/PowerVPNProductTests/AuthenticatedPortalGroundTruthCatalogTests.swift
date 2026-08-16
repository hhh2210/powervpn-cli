import Foundation
import PowerVPNCore
import Testing
@preconcurrency import XPC

@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Ground-truth catalog shape tests.
///
/// The fixture replicates the value-free structural report captured from the
/// official client's session on 2026-08-15
/// (`~/scratch-data/powervpn-surge-capture-2026-08-14/intergration-structure-report.txt`):
/// every element, every attribute, at the exact reported length and format
/// class, with synthetic values only. `nc`, `login21`, and `login52` are
/// structural labels named by the report itself; all other values are
@Suite struct AuthenticatedPortalGroundTruthTests {
  @Test func groundTruthShapedCatalogMapsCompletely() throws {
    let fixture = try authenticatedSnapshot(resourceXML: groundTruthCatalogXML)
    defer { fixture.erase() }

    let (candidates, failure) = AuthenticatedPortalSnapshotMapper.mapClassified(
      fixture.snapshot
    )
    #expect(failure == nil)
    #expect(candidates.count == 2)
    #expect(candidates.map(\.summary.displayName) == ["login21", "login52"])
    #expect(Set(candidates.map(\.summary.handle)).count == 2)
    let generation = fixture.snapshot.selectionGenerationID.uuidString.lowercased()
    for (tunnelIndex, candidate) in candidates.enumerated() {
      #expect(
        candidate.summary.handle.split(separator: ":").map(String.init)
          == ["portal", generation, "nc", "0", "tunnel", String(tunnelIndex)]
      )
    }
    #expect(groundTruthPSKSource.utf8.count == 16)
    #expect(groundTruthClientIDSource.utf8.count == 20)
    // The ground-truth shape carries PRIVATE-IP as a direct NC_RESOURCE
    // child; the official property-vip fallback (0x1000aa70c-0x1000aa894)
    // makes it common.vip, so both child items must resolve vip.
    #expect(candidates.allSatisfy { availability(of: .vip, in: $0) == .available })
    var encodedVIPByteCounts: [Int] = []
    var encodedTunnelCounts: [Int] = []
    var encodedPSKMatchesSource: [Bool] = []
    var encodedSessionIDMatchesClientID: [Bool] = []
    for candidate in candidates {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        fixture.snapshot,
        handle: candidate.summary.handle
      ) { snapshot in
        try snapshot.withEncodedStartMessage { root in
          let common = try #require(xpc_dictionary_get_value(root, "common"))
          let vip = try #require(xpc_dictionary_get_string(common, "vip"))
          let psk = try #require(xpc_dictionary_get_string(common, "psk"))
          let sessionID = try #require(xpc_dictionary_get_string(common, "sessionid"))
          let tunnels = try #require(xpc_dictionary_get_value(root, "tunnels"))
          encodedVIPByteCounts.append(String(cString: vip).utf8.count)
          encodedTunnelCounts.append(xpc_array_get_count(tunnels))
          encodedPSKMatchesSource.append(
            String(cString: psk).utf8.elementsEqual(groundTruthPSKSource.utf8)
          )
          // keyid/KEY_ID transformation belongs to the helper; the mapper must
          // preserve raw IKE/CLIENT@id bytes as common.sessionid.
          encodedSessionIDMatchesClientID.append(
            String(cString: sessionID).utf8.elementsEqual(
              groundTruthClientIDSource.utf8
            ))
        }
      }
    }
    #expect(encodedVIPByteCounts == [8, 8])
    #expect(encodedTunnelCounts == [2, 2])
    #expect(encodedPSKMatchesSource == [true, true])
    #expect(encodedSessionIDMatchesClientID == [true, true])
    #expect(candidates.allSatisfy { $0.snapshotComplete })
    #expect(candidates.allSatisfy { $0.firstMissingField == nil })
  }

  @Test func wrappedIntegrationInfoStillMaps() throws {
    // The pre-ground-truth shape (INTERGRATION_INFO wrapped in an outer root)
    // must keep mapping: the root-name acceptance is additive.
    let fixture = try authenticatedSnapshot(
      resourceXML: "<ROOT>\(groundTruthCatalogXML)</ROOT>"
    )
    defer { fixture.erase() }

    let (candidates, failure) = AuthenticatedPortalSnapshotMapper.mapClassified(
      fixture.snapshot
    )
    #expect(failure == nil)
    #expect(candidates.count == 2)
    #expect(candidates.map(\.summary.displayName) == ["login21", "login52"])
  }

  @Test func foreignRootWithoutIntegrationInfoStillFailsClosed() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: """
        <RESPONSE><RESULT code="0"/><OTHER><VERSION major="1"/></OTHER></RESPONSE>
        """
    )
    defer { fixture.erase() }

    let (candidates, failure) = AuthenticatedPortalSnapshotMapper.mapClassified(
      fixture.snapshot
    )
    #expect(candidates.isEmpty)
    #expect(failure?.stage == .scope)
    #expect(failure?.failureClass == .integrationInfoMissing)
    #expect(failure?.resourceOrdinal == nil)
    #expect(failure?.fieldPath == nil)
  }

  @Test func rootNamedWithOneIntegrationInfoChildFailsClosed() throws {
    // A same-named direct child under a root-named INTERGRATION_INFO is
    // ambiguous (XMLReader would produce an array; the official path raises
    // on duplicate structural keys), so even a single child fails closed —
    // already at snapshot mint, before any mapping.
    #expect(throws: LeadSecPortalProfileError.duplicateField) {
      _ = try authenticatedSnapshot(
        resourceXML: """
          <INTERGRATION_INFO><VERSION major="1"/>
            <INTERGRATION_INFO/>
          </INTERGRATION_INFO>
          """
      )
    }
  }

  @Test func rootNamedWithTwoIntegrationInfoChildrenFailsClosed() throws {
    #expect(throws: LeadSecPortalProfileError.duplicateField) {
      _ = try authenticatedSnapshot(
        resourceXML: """
          <INTERGRATION_INFO><INTERGRATION_INFO/><INTERGRATION_INFO/></INTERGRATION_INFO>
          """
      )
    }
  }

  @Test func nearMissRootNameStillFailsClosed() throws {
    // A root whose name only resembles INTERGRATION_INFO (case/typo variants)
    // must not be accepted; XMLReader key lookup is exact.
    let fixture = try authenticatedSnapshot(
      resourceXML: """
        <INTERGRATION-INFO><VERSION major="1"/><RESOURCE_LIST><NC_RESOURCE>
          <TUNNEL tunnel-name="login21"/>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION-INFO>
        """
    )
    defer { fixture.erase() }

    let (candidates, failure) = AuthenticatedPortalSnapshotMapper.mapClassified(
      fixture.snapshot
    )
    #expect(candidates.isEmpty)
    #expect(failure?.stage == .scope)
    #expect(failure?.failureClass == .integrationInfoMissing)
  }
}

private let groundTruthPSKSource = "P5K0ALPHA9BETA42"
private let groundTruthClientIDSource = "CLIENT9ALPHA7BETA246"

/// Synthetic replica of the captured structural report (43 elements, every
/// attribute at the reported length/format class; empty attributes stay
/// empty: `jump-mapid`, `key_id`, `pfs` (IPSEC), `ipv6`, `notice`, `cmd`,
/// `SECURED-ROUTES@name`, `dnssrv`, `dnssrv_v6`, `winssrv`).
private let groundTruthCatalogXML = """
  <INTERGRATION_INFO>
    <VERSION major="1" minor="2"/>
    <USER name="AAAAAAAA" group="AAAAAAAAAAAAAAA" type="1" access_type="1"
      logout_policy="1" jump-mapid="" internet-access="1" modify_flag="1"
      pwd_overtime="1" period_time="1" ssl_sm2="1" key_id=""
      client_jump_pskey="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      prevent_screen_shot="1" multi_network_isolation="1"/>
    <SESSION sid_name="AAAAAAAAAAAAA" id="AAAAAAAAAAAAAAAAAAAA"
      login-addr="198.51.100.200" login-time="1755200000"
      current-time="20260815000000" collect_machineinfo="1"
      detect_interval="100"/>
    <GATEWAY version="V3.2.1a"/>
    <RESOURCE_LIST>
      <NC_RESOURCE name="nc">
        <IKE version="V2">
          <SERVER ip="198.51.100.10" port="4500" id-type="AAAA"
            id="198.51.100.20"/>
          <CLIENT port="500" id-type="freefo" id="\(groundTruthClientIDSource)"/>
          <Exchange mode="auto"/>
          <PSK key="\(groundTruthPSKSource)"/>
          <ISAKMP-SA><PROPOSAL><TRANSFORMS>
            <TRANSFORM life-time="86400" enc="aes128" hash="sha1" dh="02"
              pfs="2" auth="psk"/>
          </TRANSFORMS></PROPOSAL></ISAKMP-SA>
          <IPSEC-SA><PROPOSAL><TRANSFORMS>
            <TRANSFORM life-time="1800" enc="aes256" hash="sha1" dh="02"
              pfs="" auth="psk"/>
          </TRANSFORMS></PROPOSAL></IPSEC-SA>
          <DPD dpddelay="1" dpdtimeout="1"/>
          <NAT port="1"/>
        </IKE>
        <PRIVATE-IP ip="198.51.2" ipv6="" addr="198.51.2"
          subnet="255.255.255.255"/>
        <TUNNEL tunnel-name="login21" mapid="198.51.100.21"
          negotiate-mode="1" display="1" notice="" family="4" status="1"
          icon="ic_nc1" cmd="" authority="1">
          <EXTENSIONS>
            <SECURED-ROUTE><ROUTE addr="192.0.2.128/25"/></SECURED-ROUTE>
            <SECURED-ROUTES name=""/>
            <SECURED-RANGE/>
            <SM1-MAGIC magic="1"/>
          </EXTENSIONS>
        </TUNNEL>
        <TUNNEL tunnel-name="login52" mapid="198.51.100.52"
          negotiate-mode="1" display="1" notice="" family="4" status="1"
          icon="ic_nc1" cmd="" authority="1">
          <EXTENSIONS>
            <SECURED-ROUTE><ROUTE addr="192.0.2.128/25"/></SECURED-ROUTE>
            <SECURED-ROUTES name=""/>
            <SECURED-RANGE/>
            <SM1-MAGIC magic="1"/>
          </EXTENSIONS>
        </TUNNEL>
      </NC_RESOURCE>
    </RESOURCE_LIST>
    <INTRANET_LIST/>
    <INTERNET_EXCEPTION_LIST/>
    <DNS_INFO>
      <DOMAIN_HOST dnssrv="" dnssrv_v6=""/>
      <WINS_HOST winssrv=""/>
      <HOST_LIST/>
    </DNS_INFO>
  </INTERGRATION_INFO>
  """
