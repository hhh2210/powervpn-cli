import CPortalCurl
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct SetCookieWireOrderTests {
  private let origin = try! PortalHTTPOrigin(host: "192.0.2.1", port: 4_443)

  @Test func unrelatedThenSessionUsesOnlyFinalFieldForEveryScopedRequest() async throws {
    let driver = LoginBoundaryCurlPortalDriver(
      passwordXML: acceptedLoginXML,
      passwordCookie: "VSG_SESSIONID=final-session",
      passwordSetCookieFieldCount: 2
    )

    let report = try await workflow(driver).run(
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
    let scopedCookies = driver.cookies.dropFirst()
    #expect(scopedCookies.count == 3)
    #expect(scopedCookies.allSatisfy { $0.contains("VSG_SESSIONID=final-session") })
    #expect(scopedCookies.allSatisfy { !$0.contains("unrelated=early") })
    let encoded = try JSONEncoder().encode(report)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("final-session"))
  }

  @Test func sessionThenUnrelatedUsesFallbackWithoutRescuingEarlySession() async throws {
    let driver = LoginBoundaryCurlPortalDriver(
      passwordXML: acceptedLoginXML,
      passwordCookie: "unrelated=final",
      passwordSetCookieFieldCount: 2
    )

    let report = try await workflow(driver).run(
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
    let scopedCookies = driver.cookies.dropFirst()
    #expect(scopedCookies.count == 3)
    #expect(scopedCookies.allSatisfy { $0 == " VSG_LANGUAGE=zh_CN; " })
    #expect(scopedCookies.allSatisfy { !$0.contains("VSG_SESSIONID=early-session") })
  }

  @Test func swappingTwoSessionFieldsSwapsEveryScopedCookie() async throws {
    for (discarded, final) in [
      ("first-session", "second-session"),
      ("second-session", "first-session"),
    ] {
      let driver = LoginBoundaryCurlPortalDriver(
        passwordXML: acceptedLoginXML,
        passwordCookie: "VSG_SESSIONID=\(final)",
        passwordSetCookieFieldCount: 2
      )

      let report = try await workflow(driver).run(
        credentials: syntheticCredentials(),
        platformSerial: syntheticSerial()
      )

      #expect(report.transactionAccepted)
      let scopedCookies = driver.cookies.dropFirst()
      #expect(scopedCookies.count == 3)
      #expect(scopedCookies.allSatisfy { $0.contains("VSG_SESSIONID=\(final)") })
      #expect(scopedCookies.allSatisfy { !$0.contains("VSG_SESSIONID=\(discarded)") })
    }
  }

  @Test func cResponseProjectsOnlyFinalCountAndLastWinsProvenance() throws {
    let limits = CurlPortalTransferLimits(
      timeoutMilliseconds: 1_000,
      maximumResponseBodyBytes: 1_024,
      maximumResponseHeaderBytes: 4_096,
      maximumResponseHeaderLineBytes: 1_024,
      maximumSetCookieBytes: 1_024
    )
    var cookie = Array("VSG_SESSIONID=final".utf8)
    let result = try cookie.withUnsafeMutableBufferPointer { cookie in
      var response = pvcurl_response_t()
      response.http_status = 200
      response.set_cookie = cookie.baseAddress
      response.set_cookie_length = cookie.count
      response.set_cookie_field_count = 2
      response.set_cookie_selection = PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS
      response.effective_url_exact = true
      return try CPortalCurlDriver.copyResponse(
        response,
        requireSetCookie: true,
        limits: limits
      )
    }
    defer { result.erase() }

    #expect(result.setCookieProjection == .provenLastFieldWins(fieldCount: 2))
    #expect(
      try result.setCookie?.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        == "VSG_SESSIONID=final")

    var emptyResponse = pvcurl_response_t()
    emptyResponse.http_status = 200
    emptyResponse.set_cookie_field_count = 0
    emptyResponse.set_cookie_selection = PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS
    emptyResponse.effective_url_exact = true
    let emptyResult = try CPortalCurlDriver.copyResponse(
      emptyResponse,
      requireSetCookie: false,
      limits: limits
    )
    defer { emptyResult.erase() }
    #expect(emptyResult.setCookieProjection == .provenLastFieldWins(fieldCount: 0))
    #expect(emptyResult.setCookie == nil)
  }

  private func workflow(_ driver: LoginBoundaryCurlPortalDriver) throws -> PortalLoginWorkflow {
    try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: CurlPortalTransport(allowedOrigin: origin, driver: driver),
      sleeper: SyntheticPortalSleeper()
    )
  }
}
