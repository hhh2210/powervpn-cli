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
        displayName: "raw-resource-name",
        sessionID: "helper-session-material"
      )
    )
    defer { fixture.erase() }
    let runtime = ProductReadinessRuntime(observer: MapperProductObservation())

    let resources = try runtime.resources(from: fixture.snapshot)
    #expect(resources.profileSource == .operatorApprovedFixedOrigin)
    let resource = try #require(resources.selectableResources.first)
    #expect(resources.schemaVersion == 3)
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
    #expect(report.profileSource == .operatorApprovedFixedOrigin)
    let session = try #require(
      report.fields.first { $0.field == .sessionID }
    )
    #expect(session.availability == .available)
    #expect(session.sources == [.authenticatedPortalResource])
    #expect(report.schemaVersion == 4)
    #expect(report.selectedResource == resource)
    #expect(report.firstMissingField == .ikePort)
    #expect(report.blocker == .authorizedResourceSnapshotIncomplete)
    let gateway = try #require(report.fields.first { $0.field == .gateway })
    #expect(gateway.availability == .available)
    #expect(gateway.sources == [.authenticatedPortalOrigin])

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
    #expect(!json.contains("166.111.143.19"))
    #expect(!json.contains("psk-material"))
  }

  @Test func siblingResourcesRemainIndependentCandidates() throws {
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: """
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST>
          <NC_RESOURCE><TUNNEL tunnel-name="raw-one"><IKE><CLIENT
            id="first-helper-session"/>
          </IKE></TUNNEL></NC_RESOURCE>
          <NC_RESOURCE><TUNNEL tunnel-name="raw-two"><IKE><CLIENT/>
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
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST><NC_RESOURCE>
          <TUNNEL tunnel-name="raw-resource-name"><IKE><CLIENT id="first-helper-session">
            <id>second-helper-session</id>
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
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST><NC_RESOURCE>
          <TUNNEL><IKE><CLIENT id="helper-session"/></IKE></TUNNEL>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """
    )
    defer { fixture.erase() }

    #expect(throws: AuthenticatedPortalSnapshotMappingError.missingDisplayName) {
      _ = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    }
  }

  @Test func invalidDisplayNameFailsClosed() throws {
    let invalidName = String(repeating: "a", count: 257)
    let fixture = try authenticatedSnapshot(
      cookie: "cookie-session-material",
      resourceXML: resourceXML(
        displayName: invalidName,
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
        <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST><NC_RESOURCE>
          <TUNNEL tunnel-name="first-name"><tunnel-name>second-name</tunnel-name>
            <IKE><CLIENT id="helper-session"/></IKE>
          </TUNNEL>
        </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
        """
    )
    defer { fixture.erase() }

    #expect(
      throws: AuthenticatedPortalSnapshotMappingError.duplicateField("tunnel-name")
    ) {
      _ = try AuthenticatedPortalSnapshotMapper.map(fixture.snapshot)
    }
  }
}
