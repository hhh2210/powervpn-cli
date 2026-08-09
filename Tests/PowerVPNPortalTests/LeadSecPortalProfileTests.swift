import Testing

@testable import PowerVPNPortal

@Suite struct LeadSecPortalProfileTests {
  @Test(arguments: ["0", "0x0", "  00 \n"])
  func exactNumericZeroAcceptsPassword(_ code: String) throws {
    let document = try parse(loginXML(code))
    defer { document.erase() }
    #expect(try LeadSecPortalProfile.passwordDecision(document) == .accepted)
  }

  @Test func challengeAndOtherNonzeroCodesStayDistinct() throws {
    let challenge = try parse(loginXML("0x66600011"))
    let rejected = try parse(loginXML("0x66600010"))
    defer {
      challenge.erase()
      rejected.erase()
    }
    #expect(try LeadSecPortalProfile.passwordDecision(challenge) == .challengeRequired)
    #expect(try LeadSecPortalProfile.passwordDecision(rejected) == .rejected)
  }

  @Test func missingInvalidOverflowAndDuplicateLoginCodesFailClosed() throws {
    for xml in [
      "<ROOT><RESPONSE><RESULT/></RESPONSE></ROOT>",
      loginXML("not-hex"),
      loginXML("10000000000000000"),
      "<ROOT><RESPONSE><RESULT><code>0</code><code>0</code></RESULT></RESPONSE></ROOT>",
    ] {
      let document = try parse(xml)
      defer { document.erase() }
      #expect(throws: LeadSecPortalProfileError.self) {
        _ = try LeadSecPortalProfile.passwordDecision(document)
      }
    }
  }

  @Test func resourceGateMatchesVendorMinimalPredicate() throws {
    let accepted = [
      "<ROOT/>",
      "<ROOT><RESPONSE/></ROOT>",
      "<ROOT><RESPONSE><RESULT><code>0</code></RESULT></RESPONSE></ROOT>",
      "<ROOT><INTERGRATION_INFO><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>",
      "<ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE/></RESOURCE_LIST></INTERGRATION_INFO></ROOT>",
    ]
    for xml in accepted {
      let document = try parse(xml)
      defer { document.erase() }
      #expect(try LeadSecPortalProfile.resourceAccepted(document))
    }
  }

  @Test func resourceStopCodeAndErrorNodeReject() throws {
    for xml in [
      "<ROOT><RESPONSE><RESULT><code>0x80000020</code></RESULT></RESPONSE></ROOT>",
      "<ROOT><RESPONSE><ERROR><code>1</code></ERROR></RESPONSE></ROOT>",
    ] {
      let document = try parse(xml)
      defer { document.erase() }
      #expect(throws: LeadSecPortalProfileError.resourceRejected) {
        _ = try LeadSecPortalProfile.resourceAccepted(document)
      }
    }
  }

  @Test func integrationInfoIsAWrapperRootSiblingOfResponse() throws {
    let document = try parse(
      "<ROOT><RESPONSE/><INTERGRATION_INFO><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
    )
    defer { document.erase() }
    #expect(try LeadSecPortalProfile.integrationInfo(document)?.name == "INTERGRATION_INFO")
  }

  @Test func sessionInvalidComparisonIsExactAndDoesNotWriteBackHostID() throws {
    let invalid = try parse(sessionXML("0x80000014"))
    let differentCase = try parse(sessionXML("0X80000014"))
    let normal = try parse(sessionXML("0"))
    defer {
      invalid.erase()
      differentCase.erase()
      normal.erase()
    }
    #expect(try LeadSecPortalProfile.sessionDecision(invalid) == .invalid)
    #expect(try LeadSecPortalProfile.sessionDecision(differentCase) == .accepted)
    #expect(try LeadSecPortalProfile.sessionDecision(normal) == .accepted)
  }

  @Test func missingOrStructuredSessionCodeFailsClosed() throws {
    for xml in [
      "<ROOT><RESPONSE><RESULT/></RESPONSE></ROOT>",
      "<ROOT><RESPONSE><RESULT><code><nested/></code></RESULT></RESPONSE></ROOT>",
    ] {
      let document = try parse(xml)
      defer { document.erase() }
      #expect(throws: LeadSecPortalProfileError.self) {
        _ = try LeadSecPortalProfile.sessionDecision(document)
      }
    }
  }

  private func parse(_ xml: String) throws -> PortalXMLDocument {
    try PortalXMLStructuralParser().parse(
      consuming: SecureBytes(copying: Array(xml.utf8))
    )
  }

  private func loginXML(_ code: String) -> String {
    "<ROOT><RESPONSE><RESULT><code>\(code)</code></RESULT></RESPONSE></ROOT>"
  }

  private func sessionXML(_ code: String) -> String {
    "<ROOT><RESPONSE><RESULT><code>\(code)</code><hostid>opaque</hostid></RESULT></RESPONSE></ROOT>"
  }
}
