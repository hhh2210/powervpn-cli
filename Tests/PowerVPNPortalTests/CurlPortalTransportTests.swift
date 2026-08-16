import CPortalCurl
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct CurlPortalTransportTests {
  private let origin = try! PortalHTTPOrigin(host: "192.0.2.1", port: 4_443)

  @Test func cRuntimePreflightIsNetworkFreeAndAvailableBeforeCredentialInput() throws {
    _ = try CPortalCurlDriver()
  }

  @Test func exactPasswordPostMakesSetCookieOptionalAtRawFramingBoundary() async throws {
    let driver = RecordingCurlPortalDriver()
    let transport = try CurlPortalTransport(
      allowedOrigin: origin,
      driver: driver,
      maximumResponseBytes: 1_024,
      timeout: 7
    )
    let request = try factoryPasswordRequest()
    let body = try #require(request.requestBody)
    let cookie = try #require(request.cookieHeader)

    let response = try await transport.perform(request)

    let snapshot = try #require(driver.snapshot)
    #expect(snapshot.url == "https://192.0.2.1:4443/vpn/user/auth/password")
    #expect(snapshot.host == "192.0.2.1:4443")
    #expect(snapshot.accept == PortalWireContract.accept)
    #expect(snapshot.contentType == PortalWireContract.passwordContentType)
    #expect(
      snapshot.userAgent
        == "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X synthetic-os)"
    )
    #expect(
      snapshot.body
        == "encode='1'&hardware_hash=SERIAL&password=cGFzcw==&terminal_type=mac&type=app&username=dXNlcg=="
    )
    #expect(snapshot.cookie == " VSG_LANGUAGE=zh_CN; ")
    #expect(snapshot.timeoutMilliseconds == 7_000)
    #expect(snapshot.maximumResponseBodyBytes == 1_024)
    #expect(!snapshot.requireSetCookie)
    #expect(response.statusCode == 200)
    #expect(response.setCookieProjection == .provenLastFieldWins(fieldCount: 1))
    #expect(try response.withBodyBytes { String(decoding: $0, as: UTF8.self) } == "<ok/>")
    #expect(
      try response.withSetCookieBytes { String(decoding: $0, as: UTF8.self) }
        == "VSG_SESSIONID=synthetic; Secure")
    #expect(body.count == 0)
    #expect(cookie.count == 0)
    response.erase()
  }

  @Test func rawPasswordHTTP200WithoutCookieClassifiesRejectionAndChallenge() async throws {
    for (xml, status) in [
      (loginXML("0x66600010"), PortalLoginStatus.loginRejected),
      (loginXML("0x66600011"), PortalLoginStatus.challengeRequired),
    ] {
      let driver = LoginBoundaryCurlPortalDriver(passwordXML: xml, passwordCookie: nil)
      let report = try await loginWorkflow(driver).run(
        credentials: syntheticCredentials(),
        platformSerial: syntheticSerial()
      )

      #expect(report.status == status)
      #expect(report.operations.loginRequested)
      #expect(!report.operations.loginAccepted)
      #expect(driver.paths == [PortalWireContract.passwordPath])
      #expect(driver.requirements == [false])
    }
  }

  @Test(arguments: [String?.none, "verifycode=synthetic; Secure"])
  func acceptedPasswordHTTP200ToleratesMissingOrUnsupportedCookie(
    _ passwordCookie: String?
  ) async throws {
    let driver = LoginBoundaryCurlPortalDriver(
      passwordXML: acceptedLoginXML,
      passwordCookie: passwordCookie
    )
    let report = try await loginWorkflow(driver).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )

    #expect(report.transactionAccepted)
    #expect(report.operations.resourceListRequested)
    #expect(
      driver.paths == [
        PortalWireContract.passwordPath,
        PortalWireContract.resourcePath,
        PortalWireContract.sessionCheckPath,
        PortalWireContract.logoutPath,
      ])
    #expect(
      driver.cookies
        == Array(repeating: " VSG_LANGUAGE=zh_CN; ", count: 4)
    )
  }

  @Test func acceptedPasswordHTTP200WithOneCookieProceedsThroughWorkflow() async throws {
    let driver = LoginBoundaryCurlPortalDriver(
      passwordXML: acceptedLoginXML,
      passwordCookie: syntheticSessionCookie
    )
    let report = try await loginWorkflow(driver).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )

    #expect(report.transactionAccepted)
    #expect(
      driver.paths == [
        PortalWireContract.passwordPath,
        PortalWireContract.resourcePath,
        PortalWireContract.sessionCheckPath,
        PortalWireContract.logoutPath,
      ])
    #expect(driver.requirements == [false, false, false, false])
  }

  @Test func allFourOperationsUseOneFixedProfileCurlLane() async throws {
    let driver = RecordingCurlPortalDriver()
    let transport = try CurlPortalTransport(allowedOrigin: origin, driver: driver)
    let factory = try syntheticRequestFactory()
    let credentials = try syntheticCredentials()
    let serial = try syntheticSerial()
    let passwordRequest = try factory.makePasswordRequest(
      credentials: credentials,
      platformSerial: serial
    )
    credentials.erase()
    serial.erase()
    let passwordResponse = try await transport.perform(passwordRequest)
    try factory.acceptPasswordSession(
      from: passwordResponse,
      passwordURL: passwordRequest.url
    )
    passwordResponse.erase()

    for request in [
      try factory.makeResourceRequest(),
      try factory.makeSessionCheckRequest(),
      try factory.makeLogoutRequest(),
    ] {
      let response = try await transport.perform(request)
      response.erase()
    }

    let snapshots = driver.snapshots
    #expect(snapshots.map(\.method) == [.post, .get, .get, .post])
    #expect(snapshots.map(\.requireSetCookie) == [false, false, false, false])
    #expect(
      snapshots.map(\.url) == [
        "https://192.0.2.1:4443/vpn/user/auth/password",
        "https://192.0.2.1:4443/vpn/user/portal/intergration.xml?version=2.0",
        "https://192.0.2.1:4443/vpn/user/check/session?key=hostid",
        "https://192.0.2.1:4443/vpn/user/logout",
      ])
  }

  @Test func directNearMissesNeverReachDriverAndEraseInputs() async throws {
    let driver = RecordingCurlPortalDriver()
    let transport = try CurlPortalTransport(allowedOrigin: origin, driver: driver)
    let requests = [
      directPasswordRequest(
        url: "https://192.0.2.1:4443/vpn/user/auth/password?extra=1"
      ),
      directPasswordRequest(
        url: "https://synthetic:value@192.0.2.1:4443/vpn/user/auth/password"
      ),
      directPasswordRequest(body: "encode='1'&factory_bypass=body"),
      directPasswordRequest(cookie: "VSG_LANGUAGE=en_US"),
      directPasswordRequest(userAgent: "PowerVPNPortalTests/forged"),
    ]

    for request in requests {
      let body = try #require(request.requestBody)
      let cookie = try #require(request.cookieHeader)
      await expectCurlError(.invalidRequest) {
        try await transport.perform(request)
      }
      #expect(body.count == 0)
      #expect(cookie.count == 0)
    }

    #expect(driver.snapshot == nil)
  }

  @Test func taskCancellationReachesBlockingDriverAndErasesInputs() async throws {
    let driver = BlockingCurlPortalDriver()
    let transport = try CurlPortalTransport(allowedOrigin: origin, driver: driver)
    let request = try factoryPasswordRequest()
    let body = try #require(request.requestBody)
    let cookie = try #require(request.cookieHeader)
    let task = Task { try await transport.perform(request) }
    for _ in 0..<1_000 where !driver.started { await Task.yield() }
    #expect(driver.started)

    task.cancel()
    await expectCurlError(.cancelled) { try await task.value }

    #expect(driver.cancelled)
    #expect(body.count == 0)
    #expect(cookie.count == 0)
  }

  @Test func transportCancellationReachesActiveBlockingDriver() async throws {
    let driver = BlockingCurlPortalDriver()
    let transport = try CurlPortalTransport(allowedOrigin: origin, driver: driver)
    let request = try factoryPasswordRequest()
    let task = Task { try await transport.perform(request) }
    for _ in 0..<1_000 where !driver.started { await Task.yield() }
    #expect(driver.started)

    transport.cancel()
    await expectCurlError(.cancelled) { try await task.value }
    #expect(driver.cancelled)
  }

  @Test func cStatusesMapToClosedValueFreeTransportErrors() {
    let cases: [(pvcurl_status_t, PortalTransportError?)] = [
      (PVCURL_STATUS_OK, nil),
      (PVCURL_STATUS_INVALID_ARGUMENT, .invalidRequest),
      (PVCURL_STATUS_SETUP_FAILED, .unavailable),
      (PVCURL_STATUS_TRUST_REJECTED, .trustRejected),
      (PVCURL_STATUS_REDIRECT_REJECTED, .redirectRejected),
      (PVCURL_STATUS_AUTHENTICATION_REJECTED, .authenticationChallengeRejected),
      (PVCURL_STATUS_HEADER_FRAMING_REJECTED, .invalidResponse),
      (PVCURL_STATUS_RESPONSE_TOO_LARGE, .responseTooLarge),
      (PVCURL_STATUS_CANCELLED, .cancelled),
      (PVCURL_STATUS_TIMED_OUT, .timedOut),
      (PVCURL_STATUS_UNAVAILABLE, .unavailable),
    ]
    for (status, expected) in cases {
      #expect(CPortalCurlDriver.normalizedStatus(status) == expected)
    }
  }

  @Test func foreignDriverErrorsAreCollapsedWithoutPayload() async throws {
    let sentinel = "foreign-curl-error-secret-sentinel"
    let driver = FailingCurlPortalDriver(error: CurlForeignError(value: sentinel))
    let transport = try CurlPortalTransport(allowedOrigin: origin, driver: driver)
    do {
      _ = try await transport.perform(factoryPasswordRequest())
      Issue.record("expected normalized failure")
    } catch let error as PortalTransportError {
      #expect(error == .unavailable)
      #expect(!error.description.contains(sentinel))
      #expect(!String(reflecting: error).contains(sentinel))
    }
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

  private func loginWorkflow(
    _ driver: LoginBoundaryCurlPortalDriver
  ) throws -> PortalLoginWorkflow {
    try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: CurlPortalTransport(allowedOrigin: origin, driver: driver),
      sleeper: SyntheticPortalSleeper()
    )
  }

  private func loginXML(_ code: String) -> String {
    "<RESPONSE><RESULT code=\"\(code)\"/></RESPONSE>"
  }

  private func directPasswordRequest(
    url: String = "https://192.0.2.1:4443/vpn/user/auth/password",
    body: String = "encode='1'&hardware_hash=SERIAL",
    cookie: String = " VSG_LANGUAGE=zh_CN; ",
    userAgent: String = "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X synthetic-os)"
  ) -> PortalHTTPRequest {
    PortalHTTPRequest(
      method: .post,
      url: URL(string: url)!,
      headers: try! PortalHTTPHeaders(
        accept: PortalWireContract.accept,
        contentType: PortalWireContract.passwordContentType,
        userAgent: userAgent
      ),
      body: try! SecureBytes(copying: Array(body.utf8)),
      cookieHeader: try! SecureBytes(copying: Array(cookie.utf8))
    )
  }
}
