import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Offline catalog-failure diagnostics: scope-stage failures, per-resource
/// failures on the real two-entry catalog shape (a valid `login21` entry
/// followed by a broken second entry), and the value-free-ness of the
/// classified report.
///
/// Official-contract context (PowerVPN 3.2.1 (24572) static dossier,
/// 2026-08-14): the real catalog has ≥2 NC_RESOURCE entries (login21 +
/// login52, corroborated by one `start_connection` with `tunnels.count == 2`),
/// and the official SP2 mapping parses no integer except the per-tunnel
/// status `intValue` gate (`0x100067846`–`0x1000678b7`) — `SERVER@port`,
/// lifetimes, `authority`, `family`, `negotiate-mode` are raw string
/// passthrough. Our strict-decimal leaves are therefore the top-ranked throw
/// hypothesis, so integer-leaf fixtures must pinpoint the exact field path
/// and entry 2 failing while entry 1 would have mapped. Candidate selection
/// stays fail-closed; no acceptance predicate is loosened here.
@Suite(.serialized)
struct ProductPortalDryRunCatalogFailureTests {
  // MARK: genuinely empty catalog

  @Test func emptyCatalogYieldsResourceNotFoundWithoutFailure() async throws {
    let fixture = try portalDryRunLease(resourceXML: m2ResourceXML([]))
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceNotFound)
    #expect(report.candidateCount == 0)
    #expect(report.matchingCandidateCount == 0)
    #expect(report.selectedCandidateCount == 0)
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.logoutOutcome == .accepted)
    #expect(!report.dryRunAccepted)
    #expect(fixture.transport.requestCount == 1)
  }

  // MARK: scope-stage failures

  @Test func nonDecimalMajorVersionReportsScopeMajorVersionInvalid() async throws {
    let xml = catalogXML(version: "<VERSION major=\"2x\"/>", entries: [entry("login21")])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .scope,
          failureClass: .majorVersionInvalid,
          resourceOrdinal: nil,
          fieldPath: "common.majorVersion"
        ))
  }

  @Test func missingResourceListReportsScopeResourceListMissing() async throws {
    let xml = "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/></INTERGRATION_INFO></ROOT>"
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .scope,
          failureClass: .resourceListMissing,
          resourceOrdinal: nil,
          fieldPath: nil
        ))
  }

  @Test func missingVersionReportsScopeMajorVersionMissing() async throws {
    let xml = catalogXML(version: "", entries: [entry("login21")])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure?.stage == .scope
        && report.resourceCatalogFailure?.failureClass == .majorVersionMissing
    )
  }

  @Test func duplicateVersionReportsScopeMajorVersionDuplicate() async throws {
    let xml = catalogXML(
      version: "<VERSION major=\"2\"/><VERSION major=\"2\"/>",
      entries: [entry("login21")]
    )
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(report.resourceCatalogFailure?.failureClass == .majorVersionDuplicate)
  }

  @Test func malformedMajorVersionReportsScopeMajorVersionMalformed() async throws {
    let xml = catalogXML(
      version: "<VERSION><major>2</major></VERSION>",
      entries: [entry("login21")]
    )
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(report.resourceCatalogFailure?.failureClass == .majorVersionMalformed)
  }

  @Test func erasedSnapshotReportsScopeSnapshotInaccessible() async throws {
    let fixture = try portalDryRunLease(resourceXML: m2ResourceXML(["login21"]))
    defer { fixture.erase() }
    fixture.snapshotFixture.snapshot.erase()
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.candidateCount == 0)
    #expect(report.resourceCatalogFailure?.stage == .scope)
    #expect(report.resourceCatalogFailure?.failureClass == .snapshotInaccessible)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
  }

  @Test func cleanTwoEntryCatalogSelectsExactMatchWithoutFailure() async throws {
    let xml = catalogXML(entries: [entry("login21"), entry("login52")])
    let fixture = try portalDryRunLease(resourceXML: xml)
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .accepted)
    #expect(report.candidateCount == 2)
    #expect(report.matchingCandidateCount == 1)
    #expect(report.selectedCandidateCount == 1)
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.resourceDisplayNames == ["login21", "login52"])
  }

  /// A no-match catalog must reveal the actual mapped display names (exact
  /// bytes, before any selection filtering) so the next authorized dry-run can
  /// distinguish wrong requested name from wrong mapping.
  @Test func noMatchCatalogRevealsActualDisplayNames() async throws {
    let xml = catalogXML(entries: [entry("login42"), entry("login52")])
    let fixture = try portalDryRunLease(resourceXML: xml)
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceNotFound)
    #expect(report.candidateCount == 2)
    #expect(report.matchingCandidateCount == 0)
    #expect(report.selectedCandidateCount == 0)
    #expect(report.resourceDisplayNames == ["login42", "login52"])
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
  }

  /// Integer-leaf failures must pinpoint the exact strict-decimal leaf: the
  /// official contract passes these through raw (or coerces with base-10
  /// `intValue`), so hex/malformed values here are the ranked-1 live throw.
  @Test(
    arguments: [
      ("SERVER port=\"500\"", "SERVER port=\"0x1f4\"", "common.ike_port"),
      ("life-time=\"3600\"", "life-time=\"0xe10\"", "common.ike_life_time"),
      ("life-time=\"1800\"", "life-time=\"0x708\"", "common.ipsec_life_time"),
      ("authority=\"7\"", "authority=\"0x7\"", "tunnels[].authority"),
      ("<NC_RESOURCE status=\"1\"", "<NC_RESOURCE status=\"0x1\"", "tunnels[].status"),
      ("negotiate-mode=\"3\"", "negotiate-mode=\"0x3\"", "tunnels[].negotiate-mode"),
    ]
  )
  func integerLeafFailurePinpointsExactFieldPath(
    original: String, malformed: String, expectedPath: String
  ) async throws {
    let secondEntry = entry("login52").replacingOccurrences(
      of: original,
      with: malformed
    )
    let xml = catalogXML(entries: [entry("login21"), secondEntry])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .integerInvalid,
          resourceOrdinal: 2,
          fieldPath: expectedPath
        ))
  }
  // MARK: per-resource failures on the two-entry catalog shape

  @Test func brokenSecondEntryDuplicateFieldReportsOrdinalTwo() async throws {
    let secondEntry = entry("login52").replacingOccurrences(
      of: "<CLIENT id=\"helper-session-material\"/>",
      with: "<CLIENT id=\"helper-session-material\"><id>duplicate-helper-session"
        + "</id></CLIENT>"
    )
    let xml = catalogXML(entries: [entry("login21"), secondEntry])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.candidateCount == 0)
    #expect(report.selectedCandidateCount == 0)
    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .duplicateField,
          resourceOrdinal: 2,
          fieldPath: "id"
        ))
  }

  @Test func brokenSecondEntryNonDecimalIntegerReportsOrdinalTwo() async throws {
    let secondEntry = entry("login52").replacingOccurrences(
      of: "negotiate-mode=\"3\"",
      with: "negotiate-mode=\"three\""
    )
    let xml = catalogXML(entries: [entry("login21"), secondEntry])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .integerInvalid,
          resourceOrdinal: 2,
          fieldPath: "tunnels[].negotiate-mode"
        ))
  }

  @Test func brokenSecondEntryMissingTunnelNameReportsOrdinalTwo() async throws {
    let secondEntry = entry("login52").replacingOccurrences(
      of: "<TUNNEL tunnel-name=\"login52\"",
      with: "<TUNNEL"
    )
    let xml = catalogXML(entries: [entry("login21"), secondEntry])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .displayNameMissing,
          resourceOrdinal: 2,
          fieldPath: "TUNNEL.tunnel-name"
        ))
  }

  @Test func brokenFirstEntryReportsOrdinalOne() async throws {
    let firstEntry = entry("login21").replacingOccurrences(
      of: "negotiate-mode=\"3\"",
      with: "negotiate-mode=\"three\""
    )
    let xml = catalogXML(entries: [firstEntry, entry("login52")])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(report.resourceCatalogFailure?.stage == .resource)
    #expect(report.resourceCatalogFailure?.resourceOrdinal == 1)
    #expect(report.resourceCatalogFailure?.failureClass == .integerInvalid)
  }

  @Test func missingTunnelElementReportsStructuralTunnelPath() async throws {
    let xml = catalogXML(entries: [entry("login21"), "<NC_RESOURCE status=\"1\"/>"])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .displayNameMissing,
          resourceOrdinal: 2,
          fieldPath: "TUNNEL"
        ))
  }

  @Test func oversizedDisplayNameReportsDisplayNameInvalid() async throws {
    let oversized = String(repeating: "a", count: 257)
    let xml = catalogXML(entries: [entry("login21"), entry(oversized)])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(
      report.resourceCatalogFailure
        == ProductResourceCatalogFailure(
          stage: .resource,
          failureClass: .displayNameInvalid,
          resourceOrdinal: 2,
          fieldPath: "TUNNEL.tunnel-name"
        ))
  }

  // `material_too_large` is exercised in the classifier unit test
  // (`resourceClassifierCoversEveryMappingErrorCase`): the bounded XML
  // parser rejects documents with 1 MiB+ attributes before mapping runs,
  // so no offline XML fixture can reach the composed-material limit.

  // MARK: fail-closed while entry 1 was valid

  @Test func catalogFailureNeverSelectsOrValidatesTheValidEntry() async throws {
    let secondEntry = entry("login52").replacingOccurrences(
      of: "negotiate-mode=\"3\"",
      with: "negotiate-mode=\"three\""
    )
    let xml = catalogXML(entries: [entry("login21"), secondEntry])
    let report = try await catalogRejectedReport(resourceXML: xml)

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.candidateCount == 0)
    #expect(report.matchingCandidateCount == 0)
    #expect(report.selectedCandidateCount == 0)
    #expect(!report.operations.startSnapshotValidationRequested)
    #expect(!report.startSnapshotComplete)
    #expect(!report.operations.targetRouteValidationRequested)
    #expect(!report.targetRouteCovered)
    #expect(!report.dryRunAccepted)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
  }

  // MARK: value-free-ness

  @Test func classifiedFailureContainsOnlyWhitelistedTokens() async throws {
    let secondEntry = entry("login52-secret-display").replacingOccurrences(
      of: "<CLIENT id=\"helper-session-material\"/>",
      with: "<CLIENT id=\"helper-session-material\"><id>secret-second-session"
        + "</id></CLIENT>"
    )
    let xml = catalogXML(entries: [entry("login21-secret-display"), secondEntry])
    let fixture = try portalDryRunLease(resourceXML: xml)
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    let encoded = try #require(
      String(data: JSONEncoder().encode(report), encoding: .utf8))
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(encoded.utf8)) as? [String: Any])
    let failure = try #require(
      object["resourceCatalogFailure"] as? [String: Any])

    // Exactly the four whitelisted structural keys; ordinal is a number,
    // the rest are fixed enum tokens or a known structural field path.
    #expect(Set(failure.keys) == ["stage", "failureClass", "resourceOrdinal", "fieldPath"])
    #expect(failure["stage"] as? String == "resource")
    #expect(failure["failureClass"] as? String == "duplicate_field")
    #expect(failure["resourceOrdinal"] as? Int == 2)
    #expect(failure["fieldPath"] as? String == "id")

    // No display names and no values of any kind from the resource tree.
    #expect(!encoded.contains("login21-secret-display"))
    #expect(!encoded.contains("login52-secret-display"))
    #expect(!encoded.contains("secret-second-session"))
    #expect(!encoded.contains("helper-session-material"))
    #expect(!encoded.contains("psk-material"))
    #expect(!encoded.contains("resource-map"))
    #expect(!encoded.contains("11.11"))
    #expect(!encoded.contains("10.10"))
  }

  // MARK: classifier totality

  private struct OpaqueScopeError: Error {}

  @Test func scopeClassifierCoversEveryScopeErrorCase() {
    func classify(_ error: any Error) -> ProductResourceCatalogFailure {
      AuthenticatedPortalResourceCatalogDiagnostic(
        classifyingScopeError: error
      ).failure
    }

    #expect(classify(AuthenticatedPortalSnapshotError.erased).failureClass == .snapshotInaccessible)
    #expect(
      classify(AuthenticatedPortalSnapshotError.inaccessible).failureClass
        == .snapshotInaccessible)
    #expect(
      classify(AuthenticatedPortalSnapshotError.inactiveAuthenticationGeneration).failureClass
        == .snapshotInaccessible)
    #expect(
      classify(AuthenticatedPortalSnapshotError.missingResourceList).failureClass
        == .resourceListMissing)
    #expect(
      classify(AuthenticatedPortalSnapshotError.duplicateResourceList).failureClass
        == .resourceListDuplicate)
    #expect(
      classify(AuthenticatedPortalContextBorrowError.expired).failureClass == .snapshotInaccessible)
    #expect(
      classify(AuthenticatedPortalContextBorrowError.missingIntegrationInfo).failureClass
        == .integrationInfoMissing)
    #expect(
      classify(AuthenticatedPortalContextBorrowError.missingVersion).failureClass
        == .majorVersionMissing)
    #expect(
      classify(AuthenticatedPortalContextBorrowError.missingMajorVersion).failureClass
        == .majorVersionMissing)
    #expect(
      classify(AuthenticatedPortalContextBorrowError.duplicateVersion).failureClass
        == .majorVersionDuplicate)
    #expect(
      classify(AuthenticatedPortalContextBorrowError.malformedMajorVersion).failureClass
        == .majorVersionMalformed)
    #expect(
      classify(AuthenticatedPortalResourceBorrowError.expired).failureClass == .snapshotInaccessible
    )
    #expect(
      classify(AuthenticatedPortalResourceBorrowError.notScalar).failureClass == .unclassified)
    #expect(
      classify(AuthenticatedPortalResourceBorrowError.missingAttribute).failureClass
        == .unclassified)
    #expect(
      classify(AuthenticatedPortalSnapshotMappingError.invalidInteger("common.majorVersion"))
        .failureClass == .majorVersionInvalid)
    #expect(classify(OpaqueScopeError()).failureClass == .unclassified)
  }

  @Test func resourceClassifierCoversEveryMappingErrorCase() {
    func classify(
      _ mappingError: AuthenticatedPortalSnapshotMappingError
    ) -> ProductResourceCatalogFailure {
      AuthenticatedPortalResourceCatalogDiagnostic(
        resourceOrdinal: 3,
        mappingError: mappingError
      ).failure
    }

    #expect(
      classify(.duplicateField("id"))
        == ProductResourceCatalogFailure(
          stage: .resource, failureClass: .duplicateField,
          resourceOrdinal: 3, fieldPath: "id"))
    #expect(
      classify(.missingTunnelElement)
        == ProductResourceCatalogFailure(
          stage: .resource, failureClass: .displayNameMissing,
          resourceOrdinal: 3, fieldPath: "TUNNEL"))
    #expect(
      classify(.missingDisplayName)
        == ProductResourceCatalogFailure(
          stage: .resource, failureClass: .displayNameMissing,
          resourceOrdinal: 3, fieldPath: "TUNNEL.tunnel-name"))
    #expect(
      classify(.invalidDisplayName)
        == ProductResourceCatalogFailure(
          stage: .resource, failureClass: .displayNameInvalid,
          resourceOrdinal: 3, fieldPath: "TUNNEL.tunnel-name"))
    #expect(
      classify(.invalidInteger("tunnels[].status"))
        == ProductResourceCatalogFailure(
          stage: .resource, failureClass: .integerInvalid,
          resourceOrdinal: 3, fieldPath: "tunnels[].status"))
    #expect(
      classify(.materialTooLarge)
        == ProductResourceCatalogFailure(
          stage: .resource, failureClass: .materialTooLarge,
          resourceOrdinal: 3, fieldPath: nil))
  }

  // MARK: fixtures

  private func catalogRejectedReport(
    resourceXML: String
  ) async throws -> ProductPortalDryRunReport {
    let fixture = try portalDryRunLease(resourceXML: resourceXML)
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }
    let report = await runtime.run(request())
    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.portalAcquisitionStatus == .accepted)
    #expect(report.candidateCount == 0)
    #expect(report.resourceDisplayNames == nil)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
    #expect(!report.dryRunAccepted)
    return report
  }

  private func catalogXML(
    version: String = "<VERSION major=\"2\"/>",
    entries: [String]
  ) -> String {
    "<ROOT><INTERGRATION_INFO>\(version)<RESOURCE_LIST>"
      + entries.joined()
      + "</RESOURCE_LIST></INTERGRATION_INFO></ROOT>"
  }

  private func entry(_ displayName: String) -> String {
    """
    <NC_RESOURCE status="1" mapid="resource-map"><TUNNEL tunnel-name="\(displayName)"
      authority="7" status="9" negotiate-mode="3"><IKE family="4">
      <CLIENT id="helper-session-material"/><SERVER port="500"/>
      <ISAKMP-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="null" hash="null"
        life-time="3600"/></TRANSFORMS></PROPOSAL></ISAKMP-SA>
      <IPSEC-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="aes256" hash="sha256"
        life-time="1800"/></TRANSFORMS></PROPOSAL></IPSEC-SA>
      <PSK key="psk-material"/><EXTENSIONS><PRIVATE-IP addr="10.10.10.4"/>
      <SECURED-ROUTES name="direct"><ROUTE addr="192.0.2.0/24"/>
      </SECURED-ROUTES></EXTENSIONS></IKE></TUNNEL></NC_RESOURCE>
    """
  }

  private func request() -> ProductPortalDryRunRequest {
    ProductPortalDryRunRequest(resourceDisplayName: "login21", sshTarget: .thu21)
  }
}
