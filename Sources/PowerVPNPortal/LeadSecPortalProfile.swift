enum LeadSecPortalProfileError: Error, Equatable, Sendable {
  case missingLoginCode
  case malformedLoginCode
  case duplicateField
  case malformedScalar
  case resourceRejected
  case sessionResponseMalformed
}

enum LeadSecLoginDecision: Equatable, Sendable {
  case accepted
  case challengeRequired
  case rejected
}

enum LeadSecSessionDecision: Equatable, Sendable {
  case accepted
  case invalid
}

enum LeadSecPortalProfile {
  private static let sessionInvalidCode = Array("0x80000014".utf8)

  static func passwordDecision(
    _ document: PortalXMLDocument
  ) throws -> LeadSecLoginDecision {
    guard document.root.name == "RESPONSE" else {
      throw LeadSecPortalProfileError.missingLoginCode
    }
    var resultLikeCount = document.root.attributes.reduce(0) {
      $0 + (hasASCIILocalName($1.name, equalTo: "RESULT") ? 1 : 0)
    }
    var result: PortalXMLElement?
    for child in document.root.childElements
    where hasASCIILocalName(child.name, equalTo: "RESULT") {
      resultLikeCount += 1
      if child.name == "RESULT" { result = child }
    }
    guard resultLikeCount == 1, let result else {
      throw LeadSecPortalProfileError.missingLoginCode
    }

    var codeLikeCount = result.attributes.reduce(0) {
      $0 + (hasASCIILocalName($1.name, equalTo: "code") ? 1 : 0)
    }
    for child in result.childElements where hasASCIILocalName(child.name, equalTo: "code") {
      codeLikeCount += 1
    }
    guard codeLikeCount == 1, let code = result.attribute(named: "code") else {
      throw LeadSecPortalProfileError.missingLoginCode
    }
    let numeric = try code.withValueBytes { bytes in
      guard let value = strictHex(bytes) else {
        throw LeadSecPortalProfileError.malformedLoginCode
      }
      return value
    }
    if numeric == 0 { return .accepted }
    if numeric == 0x6660_0011 { return .challengeRequired }
    return .rejected
  }

  /// Mirrors the vendor's minimal resource acceptance gate without assigning
  /// semantics to resource values. Empty/missing resource lists remain valid.
  static func resourceAccepted(_ document: PortalXMLDocument) throws -> Bool {
    if try uniqueDescendant(path: ["RESPONSE", "ERROR"], from: document.root) != nil {
      throw LeadSecPortalProfileError.resourceRejected
    }
    if let code = try scalar(at: ["RESPONSE", "RESULT", "code"], in: document) {
      let numeric = try code.withUnsafeBytes { bytes in
        guard let value = strictHex(bytes) else {
          throw LeadSecPortalProfileError.malformedScalar
        }
        return value
      }
      if numeric == 0x8000_0020 {
        throw LeadSecPortalProfileError.resourceRejected
      }
    }
    return true
  }

  static func sessionDecision(
    _ document: PortalXMLDocument
  ) throws -> LeadSecSessionDecision {
    guard let code = try scalar(at: ["RESPONSE", "RESULT", "code"], in: document) else {
      throw LeadSecPortalProfileError.sessionResponseMalformed
    }
    return try code.withUnsafeBytes { bytes in
      guard !bytes.isEmpty, bytes.count <= 64,
        bytes.allSatisfy({ (0x20...0x7e).contains($0) })
      else {
        throw LeadSecPortalProfileError.sessionResponseMalformed
      }
      return bytes.elementsEqual(sessionInvalidCode) ? .invalid : .accepted
    }
  }

  /// XMLReader's root dictionary carries `RESPONSE` and `INTERGRATION_INFO`
  /// as sibling top-level keys, i.e. in the real reply `INTERGRATION_INFO` is
  /// the XML root element itself (root shape proven by the ground-truth
  /// structural report, 2026-08-15). The portal callback then walks
  /// `root[INTERGRATION_INFO][RESOURCE_LIST][<CATEGORY>]` with plain
  /// `objectForKey:` chains (resource-list-callback dossier §3, `0x1000a8c53`
  /// and following). A root-named `INTERGRATION_INFO` is accepted only with
  /// no same-named direct child: XMLReader turns duplicate structural keys
  /// into arrays (`0x100135459`–`0x1001354c0`) and the official path raises on
  /// them, so that ambiguous shape fails closed as `.duplicateField` here.
  /// Any other root still requires a unique `INTERGRATION_INFO` child.
  static func integrationInfo(
    _ document: PortalXMLDocument
  ) throws -> PortalXMLElement? {
    if document.root.name == "INTERGRATION_INFO" {
      guard
        !document.root.childElements.contains(
          where: { $0.name == "INTERGRATION_INFO" })
      else {
        throw LeadSecPortalProfileError.duplicateField
      }
      return document.root
    }
    return try uniqueDescendant(path: ["INTERGRATION_INFO"], from: document.root)
  }

  private static func scalar(
    at path: [String],
    in document: PortalXMLDocument
  ) throws -> SecureBytes? {
    guard let element = try uniqueDescendant(path: path, from: document.root) else {
      return nil
    }
    guard element.attributes.isEmpty, element.childElements.isEmpty else {
      throw LeadSecPortalProfileError.malformedScalar
    }
    let text = element.contents.compactMap { content -> SecureBytes? in
      guard case .text(let bytes) = content else { return nil }
      return bytes
    }
    guard text.count <= 1 else { throw LeadSecPortalProfileError.malformedScalar }
    if let value = text.first { return value }
    return try SecureBytes(copying: [])
  }

  private static func uniqueDescendant(
    path: [String],
    from root: PortalXMLElement
  ) throws -> PortalXMLElement? {
    var current = root
    for name in path {
      let matches = current.childElements.filter { $0.name == name }
      guard matches.count <= 1 else { throw LeadSecPortalProfileError.duplicateField }
      guard let match = matches.first else { return nil }
      current = match
    }
    return current
  }

  private static func hasASCIILocalName(
    _ name: String,
    equalTo expected: StaticString
  ) -> Bool {
    let bytes = name.utf8
    let start = bytes.lastIndex(of: 0x3a).map { bytes.index(after: $0) } ?? bytes.startIndex
    guard bytes.distance(from: start, to: bytes.endIndex) == expected.utf8CodeUnitCount else {
      return false
    }
    return expected.withUTF8Buffer { expectedBytes in
      zip(bytes[start...], expectedBytes).allSatisfy {
        asciiLowercased($0) == asciiLowercased($1)
      }
    }
  }

  private static func asciiLowercased(_ byte: UInt8) -> UInt8 {
    (0x41...0x5a).contains(byte) ? byte + 0x20 : byte
  }

  private static func strictHex(_ raw: UnsafeRawBufferPointer) -> UInt64? {
    var lower = 0
    var upper = raw.count
    while lower < upper, isXMLWhitespace(raw[lower]) { lower += 1 }
    while upper > lower, isXMLWhitespace(raw[upper - 1]) { upper -= 1 }
    if upper - lower >= 2, raw[lower] == 0x30,
      raw[lower + 1] == 0x78 || raw[lower + 1] == 0x58
    {
      lower += 2
    }
    guard lower < upper else { return nil }
    var value: UInt64 = 0
    for byte in raw[lower..<upper] {
      let digit: UInt64
      switch byte {
      case 0x30...0x39: digit = UInt64(byte - 0x30)
      case 0x41...0x46: digit = UInt64(byte - 0x41 + 10)
      case 0x61...0x66: digit = UInt64(byte - 0x61 + 10)
      default: return nil
      }
      let (multiplied, overflow1) = value.multipliedReportingOverflow(by: 16)
      let (added, overflow2) = multiplied.addingReportingOverflow(digit)
      guard !overflow1, !overflow2 else { return nil }
      value = added
    }
    return value
  }

  private static func isXMLWhitespace(_ byte: UInt8) -> Bool {
    byte == 0x09 || byte == 0x0a || byte == 0x0d || byte == 0x20
  }
}
