import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalLogoutVerificationTests {
  @Test func timeoutDoesNotEraseCompletedValidSessionEvidence() async throws {
    let factory = try syntheticRequestFactory()
    let response = PortalHTTPResponse(
      statusCode: 200, body: try SecureBytes(copying: []),
      setCookieHeader: try SecureBytes(copying: Array(syntheticSessionCookie.utf8)),
      setCookieProjection: .provenLastFieldWins(fieldCount: 1))
    defer {
      response.erase()
      factory.eraseSession()
    }
    try factory.acceptPasswordSession(
      from: response,
      passwordURL: URL(string: "https://192.0.2.1:4443/vpn/user/auth/password")!)
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedSessionXML), .response(status: 200, body: ""),
      .response(status: 200, body: acceptedSessionXML),
    ])
    let result = await PortalLogoutVerification.run(
      factory: factory, transport: transport,
      bounder: CompletedButTimedOutBounder())
    #expect(result.status == .timedOut)
    #expect(result.verification?.after.state == .valid)
    #expect(await transport.allOwnedRequestMaterialErased())
  }

  @Test(arguments: [invalidSessionXML, "<RESPONSE><RESULT code=\"0x80000014\"/></RESPONSE>"])
  func responseLossWithInvalidatedSameCookieConfirmsClosure(_ invalidXML: String) async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .failure(.unavailable),
      .response(status: 200, body: invalidXML),
    ])
    let lease = try await acquire(transport)
    let result = await lease.logoutAndErase(verifyInvalidation: true)
    #expect(result.status == .accepted)
    #expect(result.failureClass == .postLogoutSessionRejected)
    #expect(result.verification?.before.state == .valid)
    #expect(result.verification?.after.state == .invalid)
    let snapshots = await transport.snapshots()
    #expect(snapshots.suffix(3).map(\.cookie).allSatisfy { $0 == snapshots[1].cookie })
    #expect(await transport.allOwnedRequestMaterialErased())
    #expect(await transport.allOwnedResponseMaterialErased())
    let json = try JSONEncoder().encode(result.verification)
    #expect(!String(decoding: json, as: UTF8.self).contains("VSG_SESSIONID"))
  }

  @Test(arguments: [
    acceptedSessionXML, "<html/>", "<RESPONSE><RESULT code=\"0xdeadbeef\"/></RESPONSE>",
    "<RESPONSE><RESULT code=\"0x80000014\"><code>0</code></RESULT></RESPONSE>",
  ])
  func successfulHTTPLogoutDoesNotOverrideValidOrUnknownProbe(_ after: String) async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .response(status: 200, body: ""),
      .response(status: 200, body: after),
    ])
    let result = await (try acquire(transport)).logoutAndErase(verifyInvalidation: true)
    #expect(result.status == .rejected)
    #expect(result.verification?.after.state != .invalid)
  }

  @Test func probeTimeoutNeverProvesInvalidation() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .failure(.unavailable), .failure(.timedOut),
    ])
    let result = await (try acquire(transport)).logoutAndErase(verifyInvalidation: true)
    #expect(result.status == .rejected)
    #expect(result.verification?.after.state == .unknown)
    #expect(await transport.allOwnedRequestMaterialErased())
  }

  private func acquire(_ transport: SyntheticPortalTransport) async throws
    -> AuthenticatedPortalLease
  {
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(), transport: transport,
      sleeper: SyntheticPortalSleeper())
    let result = await workflow.acquire(
      credentials: try syntheticCredentials(), platformSerial: try syntheticSerial())
    guard case .acquired(let lease) = result else { throw PortalTransportError.unavailable }
    return lease
  }
}

private struct CompletedButTimedOutBounder: PortalLogoutBounding {
  func run(_ operation: @escaping @Sendable () async -> Void) async -> Bool {
    await operation()
    return false
  }
}
