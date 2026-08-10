import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct AuthenticatedPortalSnapshotMapperTests {
  @Test func helperSessionIDComesFromResourceTreeAndOutputStaysValueFree() throws {
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: resourceXML(
        name: "raw-resource-name",
        sessionID: "helper-session-material"
      )
    )
    defer { fixture.erase() }
    let runtime = ProductReadinessRuntime(observer: MapperProductObservation())

    let resources = try runtime.resources(from: fixture.snapshot)
    let resource = try #require(resources.selectableResources.first)
    #expect(resources.schemaVersion == 2)
    #expect(resources.selectableResources.count == 1)
    #expect(resource.displayName == "raw-resource-name")
    #expect(resource.handle.hasPrefix("portal:"))
    #expect(resource.handle.hasSuffix(":nc:0"))
    let handleComponents = resource.handle.split(separator: ":")
    #expect(handleComponents.count == 4)
    #expect(UUID(uuidString: String(handleComponents[1])) != nil)

    let repeatedResources = try runtime.resources(from: fixture.snapshot)
    #expect(repeatedResources.selectableResources.first?.handle == resource.handle)

    let report = try runtime.snapshotDryRun(from: fixture.snapshot)
    let session = try #require(
      report.fields.first { $0.field == .sessionID }
    )
    #expect(session.availability == .available)
    #expect(session.sources == [.authenticatedPortalResource])
    #expect(report.schemaVersion == 3)
    #expect(report.selectedResource == resource)
    #expect(report.firstMissingField == .gateway)
    #expect(report.blocker == .authorizedResourceSnapshotIncomplete)

    let resourcesJSON = String(
      decoding: try JSONEncoder().encode(resources),
      as: UTF8.self
    )
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
    let resourcesObject = try #require(
      JSONSerialization.jsonObject(with: Data(resourcesJSON.utf8)) as? [String: Any]
    )
    let resourceObjects = try #require(
      resourcesObject["selectableResources"] as? [[String: Any]]
    )
    let resourceObject = try #require(resourceObjects.first)
    #expect(Set(resourceObject.keys) == ["displayName", "handle"])
    #expect(resourceObject["displayName"] as? String == "raw-resource-name")
    #expect(resourceObject["handle"] as? String == resource.handle)
    let snapshotObject = try #require(
      JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
    )
    let selectedObject = try #require(
      snapshotObject["selectedResource"] as? [String: Any]
    )
    #expect(selectedObject["displayName"] as? String == "raw-resource-name")
    #expect(selectedObject["handle"] as? String == resource.handle)
    #expect(resourcesJSON.contains("raw-resource-name"))
    #expect(json.contains("raw-resource-name"))
    #expect(!resourcesJSON.contains("helper-session-material"))
    #expect(!resourcesJSON.contains("cookie-session-material"))
    #expect(!json.contains("helper-session-material"))
    #expect(!json.contains("cookie-session-material"))
    #expect(!json.contains("gateway-material"))
    #expect(!json.contains("psk-material"))
  }

  @Test func siblingResourcesRemainIndependentCandidates() throws {
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: """
        <ROOT><INTERGRATION_INFO><RESOURCE_LIST>
          <NC_RESOURCE><name>raw-one</name><TUNNEL><IKE><CLIENT>
            <id>first-helper-session</id>
          </CLIENT></IKE></TUNNEL></NC_RESOURCE>
          <NC_RESOURCE><name>raw-two</name><TUNNEL><IKE><CLIENT/>
          </IKE></TUNNEL></NC_RESOURCE>
        </RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """
    )
    defer { fixture.erase() }

    let candidates = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    #expect(candidates.map(\.summary.displayName) == ["raw-one", "raw-two"])
    #expect(candidates[0].summary.handle != candidates[1].summary.handle)
    #expect(availability(of: .sessionID, in: candidates[0]) == .available)
    #expect(availability(of: .sessionID, in: candidates[1]) == .missingRequired)

    let repeated = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    #expect(repeated.map(\.summary.handle) == candidates.map(\.summary.handle))

    let report = try ProductReadinessRuntime(
      observer: MapperProductObservation()
    ).snapshotDryRun(from: fixture.snapshot)
    #expect(report.selectedResource == nil)
    #expect(report.firstMissingField == .sessionID)
    #expect(report.blocker == .resourceSelectionRequired)
  }

  @Test func duplicateMappedFieldFailsClosed() throws {
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: """
        <ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE>
          <name>raw-resource-name</name><TUNNEL><IKE><CLIENT>
            <id>first-helper-session</id><id>second-helper-session</id>
          </CLIENT></IKE></TUNNEL>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """
    )
    defer { fixture.erase() }

    #expect(
      throws: AuthenticatedPortalSnapshotMappingError.duplicateField("id")
    ) {
      _ = try ProductReadinessRuntime(
        observer: MapperProductObservation()
      ).snapshotDryRun(from: fixture.snapshot)
    }
  }

  @Test func missingDisplayNameFailsClosed() throws {
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: """
        <ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE>
          <TUNNEL><IKE><CLIENT><id>helper-session</id></CLIENT></IKE></TUNNEL>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """
    )
    defer { fixture.erase() }

    #expect(throws: AuthenticatedPortalSnapshotMappingError.invalidDisplayName) {
      _ = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    }
  }

  @Test func invalidDisplayNameFailsClosed() throws {
    let invalidName = String(repeating: "a", count: 257)
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: resourceXML(
        name: invalidName,
        sessionID: "helper-session"
      )
    )
    defer { fixture.erase() }

    #expect(throws: AuthenticatedPortalSnapshotMappingError.invalidDisplayName) {
      _ = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    }
  }

  @Test func duplicateDisplayNameFailsClosed() throws {
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: """
        <ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE>
          <name>first-name</name><name>second-name</name>
          <TUNNEL><IKE><CLIENT><id>helper-session</id></CLIENT></IKE></TUNNEL>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """
    )
    defer { fixture.erase() }

    #expect(
      throws: AuthenticatedPortalSnapshotMappingError.duplicateField("name")
    ) {
      _ = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    }
  }
}

private func availability(
  of field: VendorCharonStartField,
  in candidate: ProductResourceCandidate
) -> VendorCharonStartFieldAvailability? {
  candidate.fieldReports.first { $0.field == field }?.availability
}

private func resourceXML(name: String, sessionID: String) -> String {
  """
  <ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE>
    <name>\(name)</name><TUNNEL><IKE><CLIENT><id>\(sessionID)</id></CLIENT></IKE></TUNNEL>
  </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """
}

private final class AuthenticatedSnapshotFixture {
  let snapshot: AuthenticatedPortalSnapshot
  private let request: PortalHTTPRequest
  private let factory: PortalRequestFactory

  init(
    snapshot: AuthenticatedPortalSnapshot,
    request: PortalHTTPRequest,
    factory: PortalRequestFactory
  ) {
    self.snapshot = snapshot
    self.request = request
    self.factory = factory
  }

  func erase() {
    snapshot.erase()
    request.erase()
    factory.eraseSession()
  }
}

private func authenticatedSnapshot(
  cookie: String,
  resourceXML: String
) throws -> AuthenticatedSnapshotFixture {
  let profile = InstalledPortalProfile(
    origin: URL(string: "https://166.111.143.19:4443")!,
    portalVersion: "2.0",
    selectionSemantics: .latestPrimaryKeyFallback,
    vendorLanguageIndex: 0
  )
  let factory = try PortalRequestFactory(
    profile: profile,
    operatingSystemVersion: "product-mapper-test"
  )
  let passwordResponse = PortalHTTPResponse(
    statusCode: 200,
    body: try SecureBytes(copying: Array("<ROOT/>".utf8)),
    setCookieHeader: try SecureBytes(
      copying: Array("VSG_SESSIONID=\(cookie); Path=/; Secure".utf8)
    ),
    setCookieProjection: .provenSingleWireHeader
  )
  defer { passwordResponse.erase() }
  try factory.acceptPasswordSession(
    from: passwordResponse,
    passwordURL: URL(
      string: "https://166.111.143.19:4443/vpn/user/auth/password"
    )!
  )
  let request = try factory.makeResourceRequest()
  do {
    let document = try PortalXMLStructuralParser().parse(
      consuming: SecureBytes(copying: Array(resourceXML.utf8))
    )
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: document
    )
    return AuthenticatedSnapshotFixture(
      snapshot: snapshot,
      request: request,
      factory: factory
    )
  } catch {
    request.erase()
    factory.eraseSession()
    throw error
  }
}

private struct MapperProductObservation: ProductReadinessObserving {
  func observe() -> ProductReadinessObservation {
    ProductReadinessObservation(
      installedVersion: "3.2.1",
      installedBuild: "24572",
      installedArchitectures: ["x86_64"],
      officialGUIRunning: false,
      helperAvailable: true,
      generation: VendorHelperGenerationSnapshot(
        launchdObserved: true,
        running: false,
        inactiveConfirmed: true,
        activeCount: 0,
        pid: nil,
        runs: 19
      ),
      directXPCStatus: .notProbed,
      directXPCPreflightSafe: true,
      profileSource: .sealedInstalledConfiguration,
      resourceSource: .unavailable,
      resourceCandidates: []
    )
  }
}
