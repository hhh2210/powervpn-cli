import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalRequestFactoryTests {
  @Test func emitsExactSealedR2Requests() throws {
    let profile = syntheticPortalProfile()
    let factory = try PortalRequestFactory(
      profile: profile,
      operatingSystemVersion: "Version 14.6 (Build SYNTHETIC)"
    )
    let credentials = try syntheticCredentials()
    let serial = try syntheticSerial()
    defer {
      credentials.erase()
      serial.erase()
      factory.eraseSession()
    }

    let password = try factory.makePasswordRequest(
      credentials: credentials,
      platformSerial: serial
    )
    #expect(password.method == .post)
    #expect(
      password.url.absoluteString
        == "https://166.111.143.19:4443/vpn/user/auth/password"
    )
    #expect(password.headers.accept == "*/*")
    #expect(password.headers.contentType == "text/xml")
    #expect(password.hasOperationProof(.password))
    #expect(!password.hasOperationProof(.resource))
    #expect(
      password.headers.userAgent
        == "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X Version 14.6 (Build SYNTHETIC))"
    )
    #expect(
      try decode(password.requestBody)
        == "encode='1'&hardware_hash=SERIAL&password=cGFzcw==&terminal_type=mac&type=app&username=dXNlcg=="
    )
    #expect(try decode(password.cookieHeader) == " VSG_LANGUAGE=zh_CN; ")

    let response = PortalHTTPResponse(
      statusCode: 200,
      body: try SecureBytes(copying: []),
      setCookieHeader: try SecureBytes(copying: Array(syntheticSessionCookie.utf8)),
      setCookieProjection: .provenSingleWireHeader
    )
    defer { response.erase() }
    try factory.acceptPasswordSession(from: response, passwordURL: password.url)

    let resource = try factory.makeResourceRequest()
    let session = try factory.makeSessionCheckRequest()
    let logout = try factory.makeLogoutRequest()
    defer {
      password.erase()
      resource.erase()
      session.erase()
      logout.erase()
    }

    #expect(resource.method == .get)
    #expect(
      resource.url.absoluteString
        == "https://166.111.143.19:4443/vpn/user/portal/intergration.xml?version=2.0"
    )
    #expect(session.method == .get)
    #expect(
      session.url.absoluteString
        == "https://166.111.143.19:4443/vpn/user/check/session?key=hostid"
    )
    #expect(logout.method == .post)
    #expect(logout.url.absoluteString == "https://166.111.143.19:4443/vpn/user/logout")
    for (request, operation) in [
      (resource, PortalRequestOperation.resource),
      (session, .session),
      (logout, .logout),
    ] {
      #expect(request.headers.accept == "*/*")
      #expect(request.headers.contentType == nil)
      #expect(try decode(request.cookieHeader) == expectedAuthenticatedCookie)
      #expect(request.requestBody == nil)
      #expect(request.hasOperationProof(operation))
      #expect(!request.hasOperationProof(.password))
    }
  }

  @Test func responseWithoutAllowlistedSessionCookieFailsClosed() throws {
    let factory = try PortalRequestFactory(
      profile: syntheticPortalProfile(),
      operatingSystemVersion: "synthetic"
    )
    defer { factory.eraseSession() }
    let response = PortalHTTPResponse(
      statusCode: 200,
      body: try SecureBytes(copying: []),
      setCookieHeader: try SecureBytes(copying: Array("OTHER=value".utf8)),
      setCookieProjection: .provenSingleWireHeader
    )
    defer { response.erase() }
    #expect(throws: LeadSecPortalCookieJarError.unsupportedSetCookie) {
      try factory.acceptPasswordSession(
        from: response,
        passwordURL: URL(
          string: "https://166.111.143.19:4443/vpn/user/auth/password"
        )!
      )
    }
    #expect(factory.retainedSessionByteCount == 0)
  }

  @Test func foundationSetCookieProjectionFailsClosedAsAmbiguous() throws {
    let factory = try PortalRequestFactory(
      profile: syntheticPortalProfile(),
      operatingSystemVersion: "synthetic"
    )
    defer { factory.eraseSession() }
    let response = PortalHTTPResponse(
      statusCode: 200,
      body: try SecureBytes(copying: []),
      setCookieHeader: try SecureBytes(copying: Array(syntheticSessionCookie.utf8)),
      setCookieProjection: .foundationFoldedValue
    )
    defer { response.erase() }

    #expect(throws: LeadSecPortalCookieJarError.ambiguousSetCookieFraming) {
      try factory.acceptPasswordSession(
        from: response,
        passwordURL: URL(
          string: "https://166.111.143.19:4443/vpn/user/auth/password"
        )!
      )
    }
    #expect(factory.retainedSessionByteCount == 0)
  }

  @Test func nonOriginProfileIsRejectedBeforeAnyRequest() {
    let profile = InstalledPortalProfile(
      origin: URL(string: "https://portal.invalid:4443/base?manual=value")!,
      portalVersion: "2.0",
      selectionSemantics: .latestPrimaryKeyFallback,
      vendorLanguageIndex: 0
    )
    #expect(throws: PortalRequestFactoryError.invalidProfile) {
      _ = try PortalRequestFactory(
        profile: profile,
        operatingSystemVersion: "synthetic"
      )
    }
  }

  private var expectedAuthenticatedCookie: String {
    "VSG_SESSIONID=synthetic ORIGINURL=https://166.111.143.19:4443/vpn/user/auth/password;  VSG_LANGUAGE=zh_CN; "
  }

  private func decode(_ bytes: SecureBytes?) throws -> String? {
    try bytes?.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
  }
}
