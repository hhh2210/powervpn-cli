import Testing

@testable import PowerVPNPortal

@Suite struct LeadSecPortalProfileTests {
  @Test(arguments: ["0", "0x0", "0X000", "000000", "\t 00\r\n"])
  func exactNumericZeroAcceptsPassword(_ code: String) throws {
    let document = try parse(loginXML(code))
    defer { document.erase() }
    #expect(try LeadSecPortalProfile.passwordDecision(document) == .accepted)
  }

  @Test(arguments: ["0x66600011", "0X66600011", "000066600011", " 66600011\n"])
  func challengeFormsRemainDistinct(_ code: String) throws {
    let document = try parse(loginXML(code))
    defer { document.erase() }
    #expect(try LeadSecPortalProfile.passwordDecision(document) == .challengeRequired)
  }

  @Test(arguments: ["1", "0X66600010", "ffffffffffffffff"])
  func validOtherNonzeroCodesReject(_ code: String) throws {
    let document = try parse(loginXML(code))
    defer { document.erase() }
    #expect(try LeadSecPortalProfile.passwordDecision(document) == .rejected)
  }

  @Test(arguments: [
    "", " \t\r\n", "not-hex", "0x", "0xg", "0junk", "+0", "-0", "0x0junk",
    "10000000000000000",
  ])
  func malformedPasswordTokensFailClosed(_ code: String) throws {
    let document = try parse(loginXML(code))
    defer { document.erase() }
    #expect(throws: LeadSecPortalProfileError.self) {
      _ = try LeadSecPortalProfile.passwordDecision(document)
    }
  }

  @Test(arguments: [
    "<ROOT><RESPONSE><RESULT code=\"0\"/></RESPONSE></ROOT>",
    "<RESPONSE/>",
    "<RESPONSE><RESULT/></RESPONSE>",
    "<RESPONSE><RESULT><code>0</code></RESULT></RESPONSE>",
    "<RESPONSE><RESULT code=\"0\"/><RESULT code=\"0\"/></RESPONSE>",
    "<RESPONSE><RESULT code=\"0\"><code>0</code></RESULT></RESPONSE>",
    "<response><RESULT code=\"0\"/></response>",
    "<RESPONSE><Result code=\"0\"/></RESPONSE>",
    "<RESPONSE><RESULT Code=\"0\"/></RESPONSE>",
    "<ns:RESPONSE xmlns:ns=\"urn:test\"><RESULT code=\"0\"/></ns:RESPONSE>",
    "<RESPONSE><RESULT xmlns:ns=\"urn:test\" ns:code=\"0\"/></RESPONSE>",
  ])
  func nonXMLReaderPasswordShapesFailClosed(_ xml: String) throws {
    let document = try parse(xml)
    defer { document.erase() }
    #expect(throws: LeadSecPortalProfileError.self) {
      _ = try LeadSecPortalProfile.passwordDecision(document)
    }
  }

  @Test(arguments: [
    "<RESPONSE RESULT=\"shadow\"><RESULT code=\"0\"/></RESPONSE>",
    "<RESPONSE><RESULT code=\"0\"/><Result code=\"0\"/></RESPONSE>",
    "<RESPONSE xmlns:ns=\"urn:test\"><RESULT code=\"0\"/><ns:RESULT code=\"0\"/></RESPONSE>",
    "<RESPONSE><RESULT code=\"0\" Code=\"shadow\"/></RESPONSE>",
    "<RESPONSE><RESULT xmlns:ns=\"urn:test\" code=\"0\" ns:code=\"shadow\"/></RESPONSE>",
    "<RESPONSE><RESULT code=\"0\"><Code/></RESULT></RESPONSE>",
    "<RESPONSE xmlns:ns=\"urn:test\"><RESULT code=\"0\"><ns:code/></RESULT></RESPONSE>",
    "<RESPONSE><Result code=\"0\"/></RESPONSE>",
    "<RESPONSE xmlns:ns=\"urn:test\"><ns:RESULT code=\"0\"/></RESPONSE>",
    "<RESPONSE><RESULT Code=\"0\"/></RESPONSE>",
    "<RESPONSE xmlns:ns=\"urn:test\"><RESULT ns:code=\"0\"/></RESPONSE>",
  ])
  func passwordKeySpaceCollisionsFailClosed(_ xml: String) throws {
    let document = try parse(xml)
    defer { document.erase() }
    #expect(throws: LeadSecPortalProfileError.self) {
      _ = try LeadSecPortalProfile.passwordDecision(document)
    }
  }

  @Test func unrelatedResultAttributesAndChildrenRemainAccepted() throws {
    let document = try parse(
      "<RESPONSE unrelated=\"kept\"><RESULT code=\"0\" status=\"ok\"><message/></RESULT></RESPONSE>"
    )
    defer { document.erase() }
    #expect(try LeadSecPortalProfile.passwordDecision(document) == .accepted)
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
    "<RESPONSE><RESULT code=\"\(code)\"/></RESPONSE>"
  }

  private func sessionXML(_ code: String) -> String {
    "<ROOT><RESPONSE><RESULT><code>\(code)</code><hostid>opaque</hostid></RESULT></RESPONSE></ROOT>"
  }
}
