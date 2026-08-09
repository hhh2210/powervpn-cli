import Testing

@testable import PowerVPNPortal

@Suite struct LeadSecPortalCookieJarTests {
  private let passwordURL = "https://portal.example.invalid:443/vpn/user/auth/password"

  @Test func sealedVendorLanguageIndexRejectsOutOfRangeValues() {
    #expect(throws: LeadSecPortalCookieJarError.invalidLanguageState) {
      _ = try LeadSecPortalCookieJar(languageIndex: -1)
    }
    #expect(throws: LeadSecPortalCookieJarError.invalidLanguageState) {
      _ = try LeadSecPortalCookieJar(languageIndex: 3)
    }
  }

  @Test func freshChineseJarContainsOnlyVendorSpacedLanguageCookie() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let header = try jar.makeOutgoingCookieHeader()
    defer {
      header.erase()
      jar.erase()
    }

    #expect(try text(header) == " VSG_LANGUAGE=zh_CN; ")
    #expect(jar.retainedSessionByteCount == 0)
  }

  @Test func freshEnglishJarPreservesVendorDoubleLeadingSpace() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 2)
    let header = try jar.makeOutgoingCookieHeader()
    defer {
      header.erase()
      jar.erase()
    }

    #expect(try text(header) == "  VSG_LANGUAGE=en_US; ")
  }

  @Test func acceptedSessionIsStoredRawWithOriginAndReused() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try secure("VSG_SESSIONID=synthetic; Path=/; Secure")
    let url = try secure(passwordURL)
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
    let first = try jar.makeOutgoingCookieHeader()
    let second = try jar.makeOutgoingCookieHeader()
    defer {
      first.erase()
      second.erase()
    }
    let expected =
      "VSG_SESSIONID=synthetic; Path=/; Secure ORIGINURL=\(passwordURL);  VSG_LANGUAGE=zh_CN; "

    #expect(try text(first) == expected)
    #expect(try text(second) == expected)
    #expect(jar.retainedSessionByteCount > setCookie.count)
  }

  @Test func englishSessionPreservesVendorTripleSpaceBeforeLanguage() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 2)
    let setCookie = try secure("VSG_SESSIONID=synthetic;")
    let url = try secure(passwordURL)
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
    let header = try jar.makeOutgoingCookieHeader()
    defer { header.erase() }

    #expect(
      try text(header)
        == "VSG_SESSIONID=synthetic; ORIGINURL=\(passwordURL);   VSG_LANGUAGE=en_US; ")
  }

  @Test(arguments: [
    "verifycode=synthetic; Secure",
    "VSG_SMC_Ticket=synthetic; Secure",
    "unknown=synthetic; Secure",
  ])
  func unsupportedPasswordCookiePrefixesFailClosed(_ value: String) throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try secure(value)
    let url = try secure(passwordURL)
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

  @Test func ambiguousCookieProjectionFailsBeforeStateMutation() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try secure("VSG_SESSIONID=synthetic;")
    let url = try secure(passwordURL)
    defer {
      setCookie.erase()
      url.erase()
      jar.erase()
    }

    for projection in [
      LeadSecSetCookieProjection.foundationFoldedValue,
      .unavailableOrAmbiguous,
    ] {
      #expect(throws: LeadSecPortalCookieJarError.ambiguousSetCookieFraming) {
        try jar.acceptPasswordResponse(
          setCookieHeader: setCookie,
          projection: projection,
          passwordURL: url
        )
      }
    }
    #expect(jar.retainedSessionByteCount == 0)
  }

  @Test(arguments: [
    "VSG_SESSIONID_EXT=synthetic;",
    "VSG_SESSIONID2=synthetic;",
    "VSG_SESSIONID=first, VSG_SESSIONID=second",
    "VSG_SESSIONID=first; Path=/, OTHER=second",
    "VSG_SESSIONID=first; VSG_SESSIONID=second",
    "VSG_SESSIONID=first; VSG_SESSIONID_EXT=second",
  ])
  func extendedOrFoldedSessionCookieFormsFailClosed(_ value: String) throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try secure(value)
    let url = try secure(passwordURL)
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

  @Test func aSecondSessionEntryFailsClosedWithoutReplacingTheFirst() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let firstCookie = try secure("VSG_SESSIONID=first;")
    let secondCookie = try secure("VSG_SESSIONID=second;")
    let url = try secure(passwordURL)
    defer {
      firstCookie.erase()
      secondCookie.erase()
      url.erase()
      jar.erase()
    }
    try jar.acceptPasswordResponse(
      setCookieHeader: firstCookie,
      projection: .provenSingleWireHeader,
      passwordURL: url
    )
    let retainedCount = jar.retainedSessionByteCount

    #expect(throws: LeadSecPortalCookieJarError.sessionAlreadyStored) {
      try jar.acceptPasswordResponse(
        setCookieHeader: secondCookie,
        projection: .provenSingleWireHeader,
        passwordURL: url
      )
    }
    #expect(jar.retainedSessionByteCount == retainedCount)
  }

  @Test func invalidURLAndControlBytesFailClosed() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try secure("VSG_SESSIONID=synthetic;")
    let wrongURL = try secure("https://portal.example.invalid/not-password")
    let controlCookie = try SecureBytes(copying: [0x56, 0x53, 0x47, 0x0a])
    let url = try secure(passwordURL)
    defer {
      setCookie.erase()
      wrongURL.erase()
      controlCookie.erase()
      url.erase()
      jar.erase()
    }

    #expect(throws: LeadSecPortalCookieJarError.invalidPasswordURL) {
      try jar.acceptPasswordResponse(
        setCookieHeader: setCookie,
        projection: .provenSingleWireHeader,
        passwordURL: wrongURL
      )
    }
    #expect(throws: LeadSecPortalCookieJarError.invalidSetCookieBytes) {
      try jar.acceptPasswordResponse(
        setCookieHeader: controlCookie,
        projection: .provenSingleWireHeader,
        passwordURL: url
      )
    }
  }

  @Test func eraseIsIdempotentAndClosesFurtherAccess() throws {
    let jar = try LeadSecPortalCookieJar(languageIndex: 0)
    let setCookie = try secure("VSG_SESSIONID=synthetic;")
    let url = try secure(passwordURL)
    defer {
      setCookie.erase()
      url.erase()
    }
    try jar.acceptPasswordResponse(
      setCookieHeader: setCookie,
      projection: .provenSingleWireHeader,
      passwordURL: url
    )

    jar.erase()
    jar.erase()

    #expect(jar.retainedSessionByteCount == 0)
    #expect(throws: LeadSecPortalCookieJarError.erased) {
      _ = try jar.makeOutgoingCookieHeader()
    }
  }
}

private func secure(_ value: String) throws -> SecureBytes {
  try SecureBytes(copying: Array(value.utf8))
}

private func text(_ bytes: SecureBytes) throws -> String {
  try bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
}
