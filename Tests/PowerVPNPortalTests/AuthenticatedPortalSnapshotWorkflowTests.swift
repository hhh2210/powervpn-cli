import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct AuthenticatedPortalSnapshotWorkflowTests {
  @Test func consumerBorrowsOneGenerationBoundSnapshotBeforeSessionCheck() async throws {
    let consumer = CapturingPortalSnapshotConsumer()
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(
        status: 200,
        body:
          "<ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE><TUNNEL><IKE><CLIENT><id>helper-session-id</id></CLIENT></IKE></TUNNEL></NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>"
      ),
      .response(status: 200, body: acceptedSessionXML),
      .response(status: 200, body: ""),
    ])
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: transport,
      sleeper: SyntheticPortalSleeper(),
      snapshotConsumer: consumer
    )

    let report = await workflow.run(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )

    #expect(report.status == .accepted)
    #expect(report.transactionAccepted)
    #expect(consumer.helperSessionIDPresent)
    #expect(consumer.helperSessionIDByteCount == 17)
    #expect(consumer.descriptor?.observedCategoryNodeCount == 1)
    #expect(consumer.retainedSnapshot?.isErased == true)
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .get, .post])
  }

  @Test func consumerFailureStillPerformsExactlyOneCleanupLogout() async throws {
    let consumer = RejectingPortalSnapshotConsumer()
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: transport,
      sleeper: SyntheticPortalSleeper(),
      snapshotConsumer: consumer
    )

    let report = await workflow.run(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )

    #expect(report.status == .authenticatedSnapshotRejected)
    #expect(report.operations.loginAccepted)
    #expect(report.operations.resourceListAccepted)
    #expect(report.operations.logoutRequested)
    #expect(report.operations.logoutAccepted)
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
  }
}

private final class CapturingPortalSnapshotConsumer:
  AuthenticatedPortalSnapshotConsuming, @unchecked Sendable
{
  private let lock = NSLock()
  private var capturedHelperSessionIDPresent = false
  private var capturedHelperSessionIDByteCount = 0
  private var capturedDescriptor: AuthenticatedPortalSnapshotDescriptor?
  private var capturedSnapshot: AuthenticatedPortalSnapshot?

  func consume(_ snapshot: AuthenticatedPortalSnapshot) async throws {
    let helperSessionIDShape = try snapshot.withResourceTree { list in
      let networkConnect = try #require(
        try list.childElements.first { $0.name == "NC_RESOURCE" }
      )
      let tunnel = try #require(
        try networkConnect.childElements.first { $0.name == "TUNNEL" }
      )
      let ike = try #require(try tunnel.childElements.first { $0.name == "IKE" })
      let client = try #require(try ike.childElements.first { $0.name == "CLIENT" })
      let id = try #require(try client.childElements.first { $0.name == "id" })
      return try id.withScalarBytes { (present: !$0.isEmpty, byteCount: $0.count) }
    }
    lock.withLock {
      capturedHelperSessionIDPresent = helperSessionIDShape.present
      capturedHelperSessionIDByteCount = helperSessionIDShape.byteCount
      capturedDescriptor = snapshot.descriptor
      capturedSnapshot = snapshot
    }
  }

  var helperSessionIDPresent: Bool { lock.withLock { capturedHelperSessionIDPresent } }
  var helperSessionIDByteCount: Int { lock.withLock { capturedHelperSessionIDByteCount } }
  var descriptor: AuthenticatedPortalSnapshotDescriptor? {
    lock.withLock { capturedDescriptor }
  }
  var retainedSnapshot: AuthenticatedPortalSnapshot? {
    lock.withLock { capturedSnapshot }
  }
}

private struct RejectingPortalSnapshotConsumer: AuthenticatedPortalSnapshotConsuming {
  enum Rejection: Error { case synthetic }

  func consume(_: AuthenticatedPortalSnapshot) async throws {
    throw Rejection.synthetic
  }
}
