import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct LeadSecPortalTransportTests {
  private let origin = try! PortalHTTPOrigin(host: "166.111.143.19", port: 4_443)

  @Test func exactPasswordPostUsesOnlyRawHeaderLane() async throws {
    let password = RoutingPortalTransport()
    let session = RoutingPortalTransport()
    let transport = composite(password: password, session: session)

    _ = try await transport.perform(factoryPasswordRequest())

    #expect(password.paths == [PortalWireContract.passwordPath])
    #expect(session.paths.isEmpty)
  }

  @Test func resourceSessionAndLogoutStayOnFoundationLane() async throws {
    let password = RoutingPortalTransport()
    let session = RoutingPortalTransport()
    let transport = composite(password: password, session: session)
    let factory = try authenticatedFactory()
    defer { factory.eraseSession() }

    for request in [
      try factory.makeResourceRequest(),
      try factory.makeSessionCheckRequest(),
      try factory.makeLogoutRequest(),
    ] {
      _ = try await transport.perform(request)
    }

    #expect(password.paths.isEmpty)
    #expect(
      session.paths == [
        PortalWireContract.resourcePath,
        PortalWireContract.sessionCheckPath,
        PortalWireContract.logoutPath,
      ])
  }

  @Test func nearMissesAreRejectedBeforeEitherLane() async throws {
    let password = RoutingPortalTransport()
    let session = RoutingPortalTransport()
    let transport = composite(password: password, session: session)
    let nearMisses: [(PortalHTTPMethod, String)] = [
      (.post, "https://166.111.143.19:4443/vpn/user/auth/password?extra=1"),
      (.post, "https://other.example.invalid/vpn/user/auth/password"),
      (.post, "https://166.111.143.19:4443/vpn/user/auth/%70assword"),
      (.post, "https://synthetic@166.111.143.19:4443/vpn/user/auth/password"),
      (.post, "https://synthetic:value@166.111.143.19:4443/vpn/user/auth/password"),
      (.get, "https://166.111.143.19:4443/vpn/user/auth/password"),
      (.get, "https://166.111.143.19:4443/vpn/user/portal/intergration.xml"),
      (.get, "https://166.111.143.19:4443/vpn/user/portal/intergration.xml?version=2.1"),
      (.get, "https://166.111.143.19:4443/vpn/user/check/session?key=other"),
      (.post, "https://166.111.143.19:4443/vpn/user/logout?extra=1"),
    ]

    for (method, url) in nearMisses {
      await expectRoutingError {
        try await transport.perform(request(method, url))
      }
    }

    #expect(password.paths.isEmpty)
    #expect(session.paths.isEmpty)
  }

  @Test func directBodyCookieAndUserAgentNearMissesReachNeitherLane() async throws {
    let password = RoutingPortalTransport()
    let session = RoutingPortalTransport()
    let transport = composite(password: password, session: session)
    let url = "https://166.111.143.19:4443/vpn/user/auth/password"
    let requests = [
      request(.post, url, body: "factory_bypass=body"),
      request(.post, url, cookie: "VSG_LANGUAGE=en_US"),
      request(.post, url, userAgent: "PowerVPNPortalTests/forged"),
    ]

    for request in requests {
      await expectRoutingError {
        try await transport.perform(request)
      }
    }

    #expect(password.paths.isEmpty)
    #expect(session.paths.isEmpty)
  }

  @Test func cancellationIsForwardedToBothLanes() {
    let password = RoutingPortalTransport()
    let session = RoutingPortalTransport()
    let transport = composite(password: password, session: session)

    transport.cancel()

    #expect(password.cancelCount == 1)
    #expect(session.cancelCount == 1)
  }

  private func composite(
    password: RoutingPortalTransport,
    session: RoutingPortalTransport
  ) -> LeadSecPortalTransport {
    LeadSecPortalTransport(
      allowedOrigin: origin,
      passwordTransport: password,
      sessionTransport: session
    )
  }

  private func factoryPasswordRequest() throws -> PortalHTTPRequest {
    let factory = try syntheticRequestFactory()
    let credentials = try syntheticCredentials()
    let serial = try syntheticSerial()
    defer {
      credentials.erase()
      serial.erase()
    }
    return try factory.makePasswordRequest(
      credentials: credentials,
      platformSerial: serial
    )
  }

  private func authenticatedFactory() throws -> PortalRequestFactory {
    let factory = try syntheticRequestFactory()
    let password = try factoryPasswordRequest()
    let response = PortalHTTPResponse(
      statusCode: 200,
      body: try SecureBytes(copying: []),
      setCookieHeader: try SecureBytes(copying: Array(syntheticSessionCookie.utf8)),
      setCookieProjection: .provenSingleWireHeader
    )
    defer {
      password.erase()
      response.erase()
    }
    try factory.acceptPasswordSession(from: response, passwordURL: password.url)
    return factory
  }

  private func request(
    _ method: PortalHTTPMethod,
    _ url: String,
    body: String? = nil,
    cookie: String = " VSG_LANGUAGE=zh_CN; ",
    userAgent: String = "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X synthetic-os)"
  ) -> PortalHTTPRequest {
    let isPassword = URL(string: url)?.path == PortalWireContract.passwordPath
    return PortalHTTPRequest(
      method: method,
      url: URL(string: url)!,
      headers: try! PortalHTTPHeaders(
        accept: PortalWireContract.accept,
        contentType: isPassword ? PortalWireContract.passwordContentType : nil,
        userAgent: userAgent
      ),
      body: try! body.map { try SecureBytes(copying: Array($0.utf8)) }
        ?? (isPassword ? try! SecureBytes(copying: Array("body=synthetic".utf8)) : nil),
      cookieHeader: try! SecureBytes(copying: Array(cookie.utf8))
    )
  }
}

private func expectRoutingError(
  _ operation: () async throws -> PortalHTTPResponse
) async {
  do {
    _ = try await operation()
    Issue.record("expected exact-route rejection")
  } catch let error as PortalTransportError {
    #expect(error == .invalidRequest)
  } catch {
    Issue.record("unexpected error category")
  }
}

private final class RoutingPortalTransport: @unchecked Sendable, PortalTransporting {
  private let lock = NSLock()
  private var observedPaths: [String] = []
  private var cancellations = 0

  var paths: [String] { lock.withLock { observedPaths } }
  var cancelCount: Int { lock.withLock { cancellations } }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    lock.withLock { observedPaths.append(request.url.path) }
    request.erase()
    return PortalHTTPResponse(
      statusCode: 200,
      body: try SecureBytes(copying: [])
    )
  }

  func cancel() {
    lock.withLock { cancellations += 1 }
  }
}
