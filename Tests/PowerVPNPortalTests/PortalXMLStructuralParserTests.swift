import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalXMLStructuralParserTests {
  @Test func preservesOrderedStructureAndConsumesInput() throws {
    let input = try secure("<root mode=\"synthetic\">left&amp;<child/>right</root>")
    let document = try PortalXMLStructuralParser().parse(consuming: input)

    #expect(input.count == 0)
    #expect(document.root.name == "root")
    #expect(try bytes(document.root.attribute(named: "mode")) == Array("synthetic".utf8))
    #expect(document.root.contents.count == 3)
    #expect(try bytes(document.root.contents[0]) == Array("left&".utf8))
    #expect(document.root.contents[1].childElement?.name == "child")
    #expect(try bytes(document.root.contents[2]) == Array("right".utf8))
  }

  @Test func everyBoundFailsClosedAtItsConfiguredLimit() throws {
    try expect(
      .inputTooLarge,
      "<r/>",
      limits: bounded(input: 3)
    )
    try expect(
      .depthLimitExceeded,
      "<r><c/></r>",
      limits: bounded(depth: 1)
    )
    try expect(
      .nodeLimitExceeded,
      "<r><c/></r>",
      limits: bounded(nodes: 1)
    )
    try expect(
      .textLimitExceeded,
      "<r>ab</r>",
      limits: bounded(text: 1)
    )
    try expect(
      .attributeLimitExceeded,
      "<r a=\"1\" b=\"2\"/>",
      limits: bounded(attributes: 1)
    )
    try expect(
      .attributeLimitExceeded,
      "<r a=\"ab\"/>",
      limits: bounded(attributeBytes: 1)
    )
    #expect(throws: PortalXMLStructuralError.invalidLimits) {
      _ = try PortalXMLStructuralParser(limits: bounded(depth: 0))
    }
  }

  @Test func dtdAndEntityDeclarationsAreForbiddenWithoutResolution() throws {
    try expect(.forbiddenDeclaration, "<!DOCTYPE r><r/>")
    try expect(
      .forbiddenDeclaration,
      "<!DOCTYPE r SYSTEM \"https://invalid.example/entity\"><r/>"
    )
    try expect(.forbiddenDeclaration, "<!DOCTYPE r [<!ENTITY x \"value\">]><r>&x;</r>")

    let utf16 = Array("<!DOCTYPE r><r/>".utf16LittleEndian)
    let input = try SecureBytes(copying: utf16)
    #expect(throws: PortalXMLStructuralError.forbiddenDeclaration) {
      _ = try PortalXMLStructuralParser().parse(consuming: input)
    }
    #expect(input.count == 0)
  }

  @Test func declarationLikeTextInsideCommentsAndCDATAIsOnlyStructuralText() throws {
    let xml =
      "<?safe <!DOCTYPE ignored?>"
      + "<r><!-- first --><!-- <!DOCTYPE ignored> --><![CDATA[<!DOCTYPE scalar>]]></r>"
    let document = try PortalXMLStructuralParser().parse(consuming: secure(xml))

    #expect(document.root.contents.count == 1)
    #expect(try bytes(document.root.contents[0]) == Array("<!DOCTYPE scalar>".utf8))
  }

  @Test func malformedDuplicateRootAndTrailingContentFailClosed() throws {
    try expect(.malformed, "<r>")
    try expect(.malformed, "<r><!--")
    // Foundation rejects these before issuing a second-root/text callback;
    // the parser deliberately normalizes its opaque parser error to malformed.
    try expect(.malformed, "<r/><second/>")
    try expect(.malformed, "<r/>synthetic-trailer")
    try expect(.malformed, "")
  }

  @Test func errorsNeverEchoMalformedInput() throws {
    let sentinel = "SYNTHETIC_XML_ERROR_SENTINEL"
    do {
      _ = try PortalXMLStructuralParser().parse(consuming: secure("<r>\(sentinel)"))
      Issue.record("malformed XML unexpectedly parsed")
    } catch {
      #expect(!String(describing: error).contains(sentinel))
      #expect(error is PortalXMLStructuralError)
    }
  }

  @Test func eraseAndDeinitCascadeZeroEveryOwnedScalar() throws {
    let observation = XMLZeroObservation()
    do {
      let parser = try PortalXMLStructuralParser { observation.record($0) }
      let xml = "<r a=\"one\">left<c b=\"two\">center</c>right</r>"
      let document = try parser.parse(consuming: secure(xml))
      #expect(observation.snapshots.isEmpty)
      document.erase()
      #expect(observation.snapshots.map(\.count).sorted() == [3, 3, 4, 5, 6])
      #expect(observation.snapshots.allSatisfy { $0.allSatisfy { $0 == 0 } })
      #expect(throws: SecureBytesError.erased) {
        _ = try document.root.attribute(named: "a")?.withValueBytes(\.count)
      }
    }
    #expect(observation.snapshots.count == 5)
  }

  @Test func declaredLegacyEncodingIsDecodedWithoutUnicodeNormalization() throws {
    var input = Array("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r a=\"".utf8)
    input.append(0xe9)
    input.append(contentsOf: Array("\">".utf8))
    input.append(0xe9)
    input.append(contentsOf: Array("</r>".utf8))

    let document = try PortalXMLStructuralParser().parse(
      consuming: SecureBytes(copying: input)
    )
    #expect(try bytes(document.root.attribute(named: "a")) == [0xc3, 0xa9])
    #expect(try bytes(document.root.contents[0]) == [0xc3, 0xa9])
  }

  @Test func undeclaredOpaqueNonXMLByteFailsClosed() throws {
    var input = Array("<r>".utf8)
    input.append(0xff)
    input.append(contentsOf: Array("</r>".utf8))
    #expect(throws: PortalXMLStructuralError.malformed) {
      _ = try PortalXMLStructuralParser().parse(consuming: SecureBytes(copying: input))
    }
  }
}

private func bounded(
  input: Int = 1_024,
  depth: Int = 8,
  nodes: Int = 32,
  text: Int = 1_024,
  attributes: Int = 8,
  attributeBytes: Int = 1_024
) -> PortalXMLLimits {
  PortalXMLLimits(
    maximumInputBytes: input,
    maximumDepth: depth,
    maximumNodes: nodes,
    maximumTextBytes: text,
    maximumAttributesPerElement: attributes,
    maximumAttributeBytes: attributeBytes
  )
}

private func secure(_ xml: String) throws -> SecureBytes {
  try SecureBytes(copying: Array(xml.utf8))
}

private func expect(
  _ error: PortalXMLStructuralError,
  _ xml: String,
  limits: PortalXMLLimits = .boundedDefault
) throws {
  let input = try secure(xml)
  #expect(throws: error) {
    _ = try PortalXMLStructuralParser(limits: limits).parse(consuming: input)
  }
  #expect(input.count == 0)
}

private func bytes(_ attribute: PortalXMLAttribute?) throws -> [UInt8] {
  try #require(attribute).withValueBytes { Array($0) }
}

private func bytes(_ content: PortalXMLContent) throws -> [UInt8] {
  try content.withTextBytes { Array($0) }
}

private final class XMLZeroObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [[UInt8]] = []

  var snapshots: [[UInt8]] { lock.withLock { storage } }

  func record(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock { storage.append(Array(bytes)) }
  }
}
