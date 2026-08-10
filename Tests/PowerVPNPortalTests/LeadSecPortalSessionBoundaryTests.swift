import Testing

@testable import PowerVPNPortal

@Suite struct LeadSecPortalSessionBoundaryTests {
  private let passwordURL = "https://portal.example.invalid:443/vpn/user/auth/password"

  @Test func cookieAttributesStayOutsideTheValidatedSessionToken() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try boundarySecure("VSG_SESSIONID=exact-token; Path=/; Secure")
    let url = try boundarySecure(passwordURL)
    defer {
      setCookie.erase()
      url.erase()
      jar.erase()
    }
    try jar.acceptPasswordResponse(
      setCookieHeader: setCookie,
      projection: .provenSingleWireHeader,
      passwordURL: url
    )
    let generation = try jar.currentAuthenticationGeneration()
    let outgoing = try jar.makeOutgoingCookieHeader()
    defer { outgoing.erase() }

    #expect(generation.isActive)
    #expect(
      try boundaryText(outgoing)
        == "VSG_SESSIONID=exact-token; Path=/; Secure ORIGINURL=\(passwordURL);  VSG_LANGUAGE=zh_CN; "
    )
  }

  @Test(arguments: [
    "VSG_SESSIONID=;",
    "VSG_SESSIONID=\"quoted\";",
    "VSG_SESSIONID=back\\slash;",
  ])
  func emptyOrNonCookieOctetSessionIDsFailClosed(_ value: String) throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try boundarySecure(value)
    let url = try boundarySecure(passwordURL)
    defer {
      setCookie.erase()
      url.erase()
      jar.erase()
    }

    #expect(throws: LeadSecPortalCookieJarError.unsupportedSetCookie) {
      try jar.acceptPasswordResponse(
        setCookieHeader: setCookie,
        projection: .provenSingleWireHeader,
        passwordURL: url
      )
    }
    #expect(jar.retainedSessionByteCount == 0)
  }
}

private func boundarySecure(_ value: String) throws -> SecureBytes {
  try SecureBytes(copying: Array(value.utf8))
}

private func boundaryText(_ bytes: SecureBytes) throws -> String {
  try bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
}
