import Foundation
import PowerVPNCore
import Testing
@preconcurrency import XPC

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct AuthenticatedPortalValidatedStartSnapshotTests {
  @Test func completeSnapshotEncodesOnlyInsideScopedBody() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)
    var escapedSnapshot: VendorCharonStartSnapshot?
    var encodedGateway: String?

    try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
      fixture.snapshot,
      handle: handle
    ) { snapshot in
      escapedSnapshot = snapshot
      try snapshot.withEncodedStartMessage { root in
        let common = try #require(xpc_dictionary_get_value(root, "common"))
        let gateway = try #require(xpc_dictionary_get_string(common, "gateway"))
        encodedGateway = String(cString: gateway)
      }
    }

    #expect(encodedGateway == "166.111.143.19")
    let retainedSnapshot = try #require(escapedSnapshot)
    #expect(
      throws: VendorCharonStartEncodingError.textMaterialUnavailable(.sessionID)
    ) {
      try retainedSnapshot.withEncodedStartMessage { _ in }
    }
  }

  @Test func mappedSnapshotWithoutVIPv6EncodesPresentEmptyWireValue() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)
    var encodedVIPv6: String?

    try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
      fixture.snapshot,
      handle: handle
    ) { snapshot in
      try snapshot.withEncodedStartMessage { root in
        let common = try #require(xpc_dictionary_get_value(root, "common"))
        let vipv6 = try #require(xpc_dictionary_get_string(common, "vipv6"))
        encodedVIPv6 = String(cString: vipv6)
      }
    }

    #expect(encodedVIPv6 == "")
  }

  @Test func malformedAndUnknownHandlesFailBeforeBody() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)
    var bodyCalled = false

    #expect(throws: AuthenticatedPortalValidatedSnapshotError.invalidResourceHandle) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        fixture.snapshot,
        handle: "not-a-resource-handle"
      ) { _ in bodyCalled = true }
    }
    #expect(!bodyCalled)

    let unknown = handle.replacingOccurrences(
      of: ":nc:0:tunnel:0",
      with: ":nc:1:tunnel:0"
    )
    #expect(throws: AuthenticatedPortalValidatedSnapshotError.resourceNotFound) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        fixture.snapshot,
        handle: unknown
      ) { _ in bodyCalled = true }
    }
    #expect(!bodyCalled)
  }

  @Test func strictHandleGrammarAndFilteredTunnelFailBeforeBody() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)
    let components = handle.split(separator: ":").map(String.init)
    var bodyCalled = false

    let invalidHandles = [
      components.prefix(4).joined(separator: ":"),
      replacingHandleComponent(components, at: 3, with: "00"),
      replacingHandleComponent(components, at: 5, with: "00"),
    ]
    for invalidHandle in invalidHandles {
      #expect(throws: AuthenticatedPortalValidatedSnapshotError.invalidResourceHandle) {
        try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
          fixture.snapshot,
          handle: invalidHandle
        ) { _ in bodyCalled = true }
      }
    }

    for (index, value) in [(3, "1"), (5, "1")] {
      #expect(throws: AuthenticatedPortalValidatedSnapshotError.resourceNotFound) {
        try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
          fixture.snapshot,
          handle: replacingHandleComponent(components, at: index, with: value)
        ) { _ in bodyCalled = true }
      }
    }
    #expect(!bodyCalled)

    let filtered = try authenticatedSnapshot(
      resourceXML: filteredFirstCompleteSecondSP2XML
    )
    defer { filtered.erase() }
    let acceptedHandle = try resourceHandle(in: filtered.snapshot)
    var acceptedEncodedIndex: Int?
    try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
      filtered.snapshot,
      handle: acceptedHandle
    ) { snapshot in
      acceptedEncodedIndex = snapshot.selectedTunnelEncodedIndex
      #expect(snapshot.tunnelCount == 1)
    }
    #expect(acceptedEncodedIndex == 0)
    let filteredHandle = acceptedHandle.replacingOccurrences(
      of: ":tunnel:1",
      with: ":tunnel:0"
    )
    #expect(throws: AuthenticatedPortalValidatedSnapshotError.resourceNotFound) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        filtered.snapshot,
        handle: filteredHandle
      ) { _ in bodyCalled = true }
    }
    #expect(!bodyCalled)
  }

  @Test func uppercaseGenerationAliasFailsClosed() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)
    var components = handle.split(separator: ":").map(String.init)
    components[1] = components[1].uppercased()

    #expect(throws: AuthenticatedPortalValidatedSnapshotError.invalidResourceHandle) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        fixture.snapshot,
        handle: components.joined(separator: ":")
      ) { _ in Issue.record("uppercase alias entered scoped body") }
    }
  }

  @Test func foreignGenerationFailsClosed() throws {
    let first = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    let second = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer {
      first.erase()
      second.erase()
    }
    let foreignHandle = try resourceHandle(in: first.snapshot)

    #expect(
      throws: AuthenticatedPortalValidatedSnapshotError.resourceGenerationMismatch
    ) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        second.snapshot,
        handle: foreignHandle
      ) { _ in Issue.record("foreign generation entered scoped body") }
    }
  }

  @Test func erasedSnapshotCannotReenterScopedBody() throws {
    let fixture = try authenticatedSnapshot(resourceXML: completeValidatedSP2XML)
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)
    fixture.snapshot.erase()

    #expect(throws: AuthenticatedPortalSnapshotError.erased) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        fixture.snapshot,
        handle: handle
      ) { _ in Issue.record("erased snapshot entered scoped body") }
    }
  }

  @Test func incompleteResourceNeverExposesCoreSnapshot() throws {
    let fixture = try authenticatedSnapshot(
      resourceXML: resourceXML(
        displayName: "Campus NC",
        sessionID: "helper-session-material"
      )
    )
    defer { fixture.erase() }
    let handle = try resourceHandle(in: fixture.snapshot)

    #expect(
      throws: AuthenticatedPortalValidatedSnapshotError.incompleteSnapshot(.ikePort)
    ) {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        fixture.snapshot,
        handle: handle
      ) { _ in Issue.record("incomplete snapshot entered scoped body") }
    }
  }
}

private func resourceHandle(in snapshot: AuthenticatedPortalSnapshot) throws -> String {
  try #require(AuthenticatedPortalSnapshotMapper.map(snapshot).first).summary.handle
}

private func replacingHandleComponent(
  _ components: [String],
  at index: Int,
  with replacement: String
) -> String {
  var copy = components
  copy[index] = replacement
  return copy.joined(separator: ":")
}

private let completeValidatedSP2XML = """
  <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
    <NC_RESOURCE status="1" mapid="resource-map"><TUNNEL tunnel-name="Campus NC"
      authority="7" status="9" negotiate-mode="3">
      <IKE family="4"><CLIENT id="helper-session-material"/><SERVER port="500"/>
        <ISAKMP-SA><PROPOSAL><TRANSFORMS>
          <TRANSFORM enc="null" hash="null" life-time="3600"/>
        </TRANSFORMS></PROPOSAL></ISAKMP-SA>
        <IPSEC-SA><PROPOSAL><TRANSFORMS>
          <TRANSFORM enc="aes256" hash="sha256" life-time="1800"/>
        </TRANSFORMS></PROPOSAL></IPSEC-SA><PSK key="psk-material"/>
        <EXTENSIONS><PRIVATE-IP addr="10.10.10.4"/>
          <SECURED-ROUTES name="direct"><ROUTE addr="10.1.2.3/24"/></SECURED-ROUTES>
        </EXTENSIONS>
      </IKE>
    </TUNNEL></NC_RESOURCE>
  </RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """

private let filteredFirstCompleteSecondSP2XML = """
  <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
    <NC_RESOURCE mapid="resource-map">
      <IKE><CLIENT id="helper-session-material"/><SERVER port="500"/>
        <ISAKMP-SA><PROPOSAL><TRANSFORMS>
          <TRANSFORM enc="null" hash="null" life-time="3600"/>
        </TRANSFORMS></PROPOSAL></ISAKMP-SA>
        <IPSEC-SA><PROPOSAL><TRANSFORMS>
          <TRANSFORM enc="aes256" hash="sha256" life-time="1800"/>
        </TRANSFORMS></PROPOSAL></IPSEC-SA><PSK key="psk-material"/>
        <EXTENSIONS><PRIVATE-IP addr="10.10.10.4"/></EXTENSIONS>
      </IKE>
      <TUNNEL tunnel-name="filtered" status="0"/>
      <TUNNEL tunnel-name="accepted" authority="7" status="9" negotiate-mode="3">
        <IKE family="4"><EXTENSIONS>
          <SECURED-ROUTES name="direct"><ROUTE addr="10.1.2.3/24"/></SECURED-ROUTES>
        </EXTENSIONS></IKE>
      </TUNNEL>
    </NC_RESOURCE>
  </RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """
