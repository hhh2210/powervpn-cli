import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct NativeTunnelTests {
  @Test(arguments: [
    (PortalLoginStatus.transportRejected, NativeTunnelFailure.portalUnavailable),
    (.resourceListRejected, .portalUnavailable),
    (.authenticatedSnapshotRejected, .portalUnavailable),
    (.loginRejected, .portalRejected), (.credentialInputRejected, .portalRejected),
    (.tlsRejected, .portalConfigurationRejected), (.cancelled, .cancelled),
  ])
  func portalFailurePreservesItsClass(status: PortalLoginStatus, expected: NativeTunnelFailure) {
    let report = PortalLoginReport(
      status: status,
      operations: .init(
        loginRequested: true, loginAccepted: false,
        sessionCheckRequested: false, sessionCheckAccepted: false,
        resourceListRequested: false, resourceListAccepted: false,
        logoutRequested: false, logoutAccepted: false),
      ownedMaterial: .init(
        credentialsErased: true, requestBodiesErased: true,
        responseBodiesErased: true, sessionMaterialErased: true))
    #expect(NativeTunnelFailure.portalFailure(report) == expected)
    let failure = NativeTunnelOpenFailure(portal: report)
    #expect(failure.serverContactRequested)
    #expect(!failure.helperMutationRequested)
    #expect(failure.cleanupVerified == (status == .loginRejected))
  }

  @Test func repeatedAndConcurrentShutdownDoesNotTurnFailedLogoutIntoSuccess() async throws {
    let fixture = try authenticatedSnapshot(
      resourceXML:
        "<ROOT><INTERGRATION_INFO><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>")
    defer { fixture.erase() }
    let transport = NativeLogoutTransport()
    let lease = AuthenticatedPortalLease(
      snapshot: fixture.snapshot, factory: fixture.factory,
      transport: transport, logoutBounder: NativeLogoutBounder())
    let tunnel = NativeTunnel(
      targetIPv4: 0xC000_0215, targetHost: "192.0.2.21",
      name: "powervpn-synthetic", lease: lease, vici: "/synthetic-unused",
      helper: "/synthetic-unused")
    let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
      for _ in 0..<4 { group.addTask { await tunnel.shutdown() } }
      var values: [Bool] = []
      for await result in group { values.append(result) }
      return values
    }
    #expect(results == [false, false, false, false])
    #expect(await tunnel.shutdown() == false)
    #expect(transport.calls == 3)
    let receipt = await tunnel.shutdownReport()
    #expect(receipt.localCleanupVerified)
    #expect(!receipt.portalCleanupVerified)
    #expect(receipt.portalStatus == "rejected")
  }

  @Test func authoritativeInventoryIncludesOrphanCredentialsAndRejectsUnavailableQuery() throws {
    let response: (VICIMessage) throws -> Data = { message in
      Data([VICIPacketOperation.commandResponse.rawValue]) + (try VICIMessageCodec.encode(message))
    }
    let transport = NativeInventoryTransport(responses: [
      Data([VICIPacketOperation.eventConfirm.rawValue]),
      try response(.init(elements: [])),
      Data([VICIPacketOperation.eventConfirm.rawValue]),
      try response(.init(elements: [.list("conns", ["powervpn-conn"])])),
      try response(.init(elements: [.list("keys", ["powervpn-orphan-key"])])),
    ])
    let session = VICISession(transport: transport)
    #expect(try nativeSessionNames(session) == ["powervpn-conn", "powervpn-orphan-key"])
    let request = try VICINamedRequest.decode(payload: transport.sent[1])
    #expect(request.command == "list-sas")
    #expect(request.message.elements.isEmpty)
    #expect(throws: VICITransportError.self) { try nativeSessionNames(session) }
  }
}

private final class NativeLogoutTransport: PortalTransporting, @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  var calls: Int { lock.withLock { count } }
  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    lock.withLock { count += 1 }
    return PortalHTTPResponse(statusCode: 500, body: try SecureBytes(copying: []))
  }
  func cancel() {}
}

private struct NativeLogoutBounder: PortalLogoutBounding {
  func run(_ operation: @escaping @Sendable () async -> Void) async -> Bool {
    await operation()
    return true
  }
}

private final class NativeInventoryTransport: VICIFrameTransport {
  var responses: [Data]
  var sent: [Data] = []
  init(responses: [Data]) { self.responses = responses }
  func send(payload: Data) throws -> Int {
    sent.append(payload)
    return payload.count + 4
  }
  func receive() throws -> VICIReceivedFrame {
    guard !responses.isEmpty else { throw VICITransportError.timeout(.readHeader) }
    let payload = responses.removeFirst()
    return VICIReceivedFrame(payload: payload, wireByteCount: payload.count + 4)
  }
  func close() {}
}

@Suite struct NativeOpenPolicyTests {
  // MARK: restart / retry decision

  private func step(
    _ failure: NativeTunnelFailure, attempt: Int = 1, restarted: Bool = false,
    cleanup: Bool = true, cancelled: Bool = false, canRestart: Bool = true
  ) -> NativeOpenNextStep {
    .after(
      failure: failure, attempt: attempt, attempts: 3, charonRestarted: restarted,
      cleanupVerified: cleanup, cancelled: cancelled, helperCanRestart: canRestart)
  }

  @Test func localVirtualIPFailureRestartsCharonExactlyOnce() {
    #expect(step(.localVirtualIPFailed) == .restartCharonThenRetry)
    #expect(step(.localVirtualIPFailed, restarted: true) == .stop)
    #expect(step(.localVirtualIPFailed, canRestart: false) == .stop)
  }

  @Test func restartNeverHappensOverUnverifiedCleanupOrCancellation() {
    #expect(step(.localVirtualIPFailed, cleanup: false) == .stop)
    #expect(step(.localVirtualIPFailed, cancelled: true) == .stop)
    #expect(step(.resourceUnavailable, cleanup: false) == .stop)
  }

  @Test func gatewayAndIKEFailuresNeverTriggerARestart() {
    for failure in [
      NativeTunnelFailure.childFailed, .ikeFailed, .routeRejected, .portalUnavailable,
    ] {
      #expect(step(failure) == .stop)
    }
  }

  @Test func resourceCatalogRetryIsBoundedByTheAttemptBudget() {
    #expect(step(.resourceUnavailable, attempt: 1) == .retryAfterDelay)
    #expect(step(.resourceUnavailable, attempt: 2) == .retryAfterDelay)
    #expect(step(.resourceUnavailable, attempt: 3) == .stop)
  }

  // MARK: user-facing mapping

  @Test func localFailureNoLongerBlamesTheGateway() {
    let local = nativeFailureDescription(.localVirtualIPFailed)
    #expect(local.contains("local fault") && !local.contains("gateway did not"))
    let local2 = NativeTunnelFailure.localVirtualIPFailed
    #expect(local2.next.contains("kickstart") && local2.next.contains("native log"))
  }

  @Test func childFailureWordingFollowsPositiveEvidenceOnly() {
    func described(_ cause: NativeFailureCause?) -> String {
      nativeFailureDescription(
        .childFailed,
        detail: cause.map { NativeFailureDetail(phase: .child, cause: $0) })
    }
    #expect(described(.gatewayRefused).contains("gateway refused"))
    #expect(described(.timedOut).contains("did not answer"))
    for neutral in [nil, NativeFailureCause.unclassified] {
      let text = described(neutral)
      #expect(text.contains("cause was not identified"))
      #expect(!text.contains("gateway"))
    }
  }

  @Test func attemptLogWritesTokensOnlyAndSanitizes() throws {
    let path = NSTemporaryDirectory() + "attempt-" + UUID().uuidString
    defer { try? FileManager.default.removeItem(atPath: path) }
    let log = NativeRotatingLog(path: path)
    NativeAttemptLog(log).record(
      "attempt=1 failed=native_child_failed keyid:#3a7f9c0b12de45a8b6c7d8e9")
    let text = try String(contentsOfFile: path, encoding: .utf8)
    #expect(text.contains("native_child_failed") && !text.contains("3a7f9c0b12de45a8"))
  }
}
