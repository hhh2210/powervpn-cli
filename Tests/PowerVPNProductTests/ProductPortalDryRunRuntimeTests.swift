import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite(.serialized)
struct ProductPortalDryRunRuntimeTests {
  @Test func acceptedSnapshotProvesRouteAndClosesValueFree() async throws {
    let fixture = try portalDryRunLease(resourceXML: m2ResourceXML(["login21"]))
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime {
      .acquired(lease)
    }

    let report = await runtime.run(request())

    #expect(report.outcome == .accepted)
    #expect(report.schemaVersion == 2)
    #expect(report.portalAcquisitionStatus == .accepted)
    #expect(report.portalTransportFailure == nil)
    #expect(report.candidateCount == 1)
    #expect(report.matchingCandidateCount == 1)
    #expect(report.selectedCandidateCount == 1)
    #expect(report.startSnapshotComplete)
    #expect(report.targetRouteCovered)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.logoutFailureClass == nil)
    #expect(report.resourceCatalogFailure == nil)
    #expect(report.ownedMaterialErased)
    #expect(report.dryRunAccepted)
    #expect(report.operations.portalAcquisitionRequested)
    #expect(report.operations.loginRequested)
    #expect(report.operations.loginAccepted)
    #expect(report.operations.resourceListRequested)
    #expect(report.operations.resourceListAccepted)
    #expect(!report.operations.sessionCheckRequested)
    #expect(report.operations.startSnapshotValidationRequested)
    #expect(report.operations.startSnapshotConstructed)
    #expect(report.operations.targetRouteValidationRequested)
    #expect(report.operations.logoutAttempted)
    #expect(report.operations.logoutAccepted)
    #expect(!report.helperMutationRequested)
    #expect(!report.sshRequested)
    #expect(!report.m2CoordinatorRequested)
    #expect(!report.containsSecrets)
    #expect(fixture.transport.requestCount == 1)
    #expect(fixture.snapshotFixture.snapshot.isErased)

    let encoded = try #require(
      String(
        data: JSONEncoder().encode(report),
        encoding: .utf8
      ))
    #expect(!encoded.contains("login21"))
    #expect(!encoded.contains("helper-session-material"))
    #expect(!encoded.contains("psk-material"))
    #expect(!encoded.contains("11.11"))
    #expect(!encoded.contains("portalTransportFailure"))
    #expect(!encoded.contains("resourceCatalogFailure"))
    #expect(!encoded.contains("logoutFailureClass"))
  }

  @Test func missingExactResourceFailsClosedAndLogsOut() async throws {
    let fixture = try portalDryRunLease(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceNotFound)
    #expect(report.candidateCount == 1)
    #expect(report.matchingCandidateCount == 0)
    #expect(report.selectedCandidateCount == 0)
    #expect(!report.startSnapshotComplete)
    #expect(!report.targetRouteCovered)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
    #expect(fixture.transport.requestCount == 1)
  }

  @Test func duplicateExactResourceFailsAmbiguousAndLogsOut() async throws {
    let fixture = try portalDryRunLease(
      resourceXML: m2ResourceXML(["login21", "login21"])
    )
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceAmbiguous)
    #expect(report.candidateCount == 2)
    #expect(report.matchingCandidateCount == 2)
    #expect(report.selectedCandidateCount == 0)
    #expect(!report.startSnapshotComplete)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
    #expect(fixture.transport.requestCount == 1)
  }

  @Test func incompleteStartSnapshotFailsClosedAndLogsOut() async throws {
    let xml = m2ResourceXML(["login21"]).replacingOccurrences(
      of: "<PSK key=\"psk-material\"/>",
      with: ""
    )
    let fixture = try portalDryRunLease(resourceXML: xml)
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .startSnapshotIncomplete)
    #expect(report.candidateCount == 1)
    #expect(report.matchingCandidateCount == 1)
    #expect(report.selectedCandidateCount == 1)
    #expect(report.operations.startSnapshotValidationRequested)
    #expect(!report.startSnapshotComplete)
    #expect(!report.operations.targetRouteValidationRequested)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
    #expect(fixture.transport.requestCount == 1)
  }

  @Test func targetOutsideSelectedRoutesFailsClosedAndLogsOut() async throws {
    let xml = m2ResourceXML(["login21"]).replacingOccurrences(
      of: "11.11.0.0/16",
      with: "10.1.2.0/24"
    )
    let fixture = try portalDryRunLease(resourceXML: xml)
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .targetRouteNotCovered)
    #expect(report.startSnapshotComplete)
    #expect(report.operations.targetRouteValidationRequested)
    #expect(!report.targetRouteCovered)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
    #expect(fixture.transport.requestCount == 1)
  }

  @Test func logoutRejectionCannotAcceptButStillErases() async throws {
    let fixture = try portalDryRunLease(
      resourceXML: m2ResourceXML(["login21"]),
      logoutStatusCode: 500
    )
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .logoutRejected)
    #expect(report.startSnapshotComplete)
    #expect(report.targetRouteCovered)
    #expect(report.logoutOutcome == .rejected)
    #expect(report.logoutFailureClass == .completedRemoteExchange)
    #expect(report.operations.logoutAttempted)
    #expect(!report.operations.logoutAccepted)
    #expect(report.ownedMaterialErased)
    #expect(!report.dryRunAccepted)
    #expect(fixture.transport.requestCount == 1)
  }

  @Test func logoutTransportFailureClassifiesTransportFailed() async throws {
    let fixture = try portalDryRunLease(
      resourceXML: m2ResourceXML(["login21"]),
      logoutTransportError: .unavailable
    )
    defer { fixture.erase() }
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .logoutRejected)
    #expect(report.logoutOutcome == .rejected)
    #expect(report.logoutFailureClass == .transportFailed)
    #expect(report.operations.logoutAttempted)
    #expect(!report.operations.logoutAccepted)
    #expect(report.ownedMaterialErased)
    #expect(!report.dryRunAccepted)
    #expect(fixture.transport.requestCount == 1)
  }

  /// Erasing the factory session invalidates the authentication generation,
  /// so the catalog borrow fails closed first and the logout request cannot
  /// be constructed: both classified fields are exposed additively.
  @Test func preErasedSessionClassifiesCatalogInaccessibleAndConstructionFailed()
    async throws
  {
    let fixture = try portalDryRunLease(resourceXML: m2ResourceXML(["login21"]))
    defer { fixture.erase() }
    fixture.eraseFactorySession()
    let lease = fixture.lease
    let runtime = ProductPortalDryRunRuntime { .acquired(lease) }

    let report = await runtime.run(request())

    #expect(report.outcome == .resourceCatalogRejected)
    #expect(report.candidateCount == 0)
    #expect(report.resourceCatalogFailure?.stage == .scope)
    #expect(report.resourceCatalogFailure?.failureClass == .snapshotInaccessible)
    #expect(report.logoutOutcome == .rejected)
    #expect(report.logoutFailureClass == .requestConstructionFailed)
    #expect(report.operations.logoutAttempted)
    #expect(!report.operations.logoutAccepted)
    #expect(report.ownedMaterialErased)
    #expect(!report.dryRunAccepted)
    // The request was never constructed, so no wire request was made.
    #expect(fixture.transport.requestCount == 0)
  }

  @Test func cancellationAfterAcquisitionStillLogsOutAndErases() async throws {
    let fixture = try portalDryRunLease(resourceXML: m2ResourceXML(["login21"]))
    defer { fixture.erase() }
    let gate = PortalDryRunAcquisitionGate(result: .acquired(fixture.lease))
    let runtime = ProductPortalDryRunRuntime { await gate.acquire() }
    let task = Task { await runtime.run(request()) }

    await gate.waitUntilEntered()
    task.cancel()
    await gate.release()
    let report = await task.value

    #expect(report.outcome == .cancelled)
    #expect(!report.operations.startSnapshotValidationRequested)
    #expect(report.operations.logoutAttempted)
    #expect(report.logoutOutcome == .accepted)
    #expect(report.ownedMaterialErased)
    #expect(!report.dryRunAccepted)
    #expect(fixture.transport.requestCount == 1)
  }

  private func request() -> ProductPortalDryRunRequest {
    ProductPortalDryRunRequest(resourceDisplayName: "login21", sshTarget: .thu21)
  }
}
