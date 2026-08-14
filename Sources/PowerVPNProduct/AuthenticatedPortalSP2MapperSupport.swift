import Darwin
import Foundation
import PowerVPNCore
import PowerVPNPortal

enum PortalSP2Tree {
  static func children(
    named name: String,
    of parent: AuthenticatedPortalResourceElement
  ) throws -> [AuthenticatedPortalResourceElement] {
    try parent.childElements.filter { $0.name == name }
  }

  static func child(
    named name: String,
    of parent: AuthenticatedPortalResourceElement
  ) throws -> AuthenticatedPortalResourceElement? {
    let matches = try children(named: name, of: parent)
    guard matches.count <= 1 else {
      throw AuthenticatedPortalSnapshotMappingError.duplicateField(name)
    }
    return matches.first
  }

  static func descendant(
    from root: AuthenticatedPortalResourceElement,
    path: [String]
  ) throws -> AuthenticatedPortalResourceElement? {
    var current: AuthenticatedPortalResourceElement? = root
    for name in path {
      guard let element = current else { return nil }
      current = try child(named: name, of: element)
    }
    return current
  }

  /// XMLReader promotes attributes directly into the containing dictionary.
  /// A same-named child becomes a nested dictionary (`text` is below it), so it
  /// is deliberately not accepted as a helper scalar.
  static func attribute(
    named name: String,
    of parent: AuthenticatedPortalResourceElement
  ) throws -> PortalSP2Scalar? {
    let childMatches = try children(named: name, of: parent)
    let attributeMatches = try parent.attributeNames.filter { $0 == name }
    guard attributeMatches.count <= 1 else {
      throw AuthenticatedPortalSnapshotMappingError.duplicateField(name)
    }
    guard childMatches.isEmpty else {
      if !attributeMatches.isEmpty {
        throw AuthenticatedPortalSnapshotMappingError.duplicateField(name)
      }
      return nil
    }
    if attributeMatches.first != nil { return .attribute(parent, name) }
    return nil
  }

  /// The installed GUI displays the first SP2 tunnel's `tunnel-name`. Like the
  /// helper, it reads this key directly from XMLReader's element dictionary,
  /// so only the attribute shape is accepted.
  static func displayName(
    of tunnel: AuthenticatedPortalResourceElement
  ) throws -> String {
    guard let scalar = try attribute(named: "tunnel-name", of: tunnel) else {
      throw AuthenticatedPortalSnapshotMappingError.missingDisplayName
    }
    return try scalar.withBytes { bytes in
      guard (1...256).contains(bytes.count), !bytes.contains(0),
        let value = String(bytes: bytes, encoding: .utf8),
        value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
      else {
        throw AuthenticatedPortalSnapshotMappingError.invalidDisplayName
      }
      return value
    }
  }
}

enum PortalSP2Scalar: @unchecked Sendable {
  case attribute(AuthenticatedPortalResourceElement, String)

  func withBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    switch self {
    case .attribute(let element, let name):
      return try element.withAttributeValueBytes(named: name, body)
    }
  }

  var byteCount: Int {
    get throws { try withBytes(\.count) }
  }

  func bytesEqual(_ expected: [UInt8]) throws -> Bool {
    try withBytes { $0.elementsEqual(expected) }
  }
}

enum PortalSP2Value {
  static func text(
    _ scalar: PortalSP2Scalar?,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartTextValue? {
    guard let scalar else { return nil }
    return VendorCharonStartTextValue(
      value: try PortalSP2BorrowedTextMaterial(scalar),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  static func integer(
    _ scalar: PortalSP2Scalar?,
    path: String,
    lineage: VendorCharonStartLineage
  ) throws -> VendorCharonStartIntegerValue? {
    guard let scalar else { return nil }
    return VendorCharonStartIntegerValue(
      value: try strictInt32(scalar, path: path),
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  static func metadataInteger(
    _ value: Int32,
    lineage: VendorCharonStartLineage
  ) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: value,
      source: .authenticatedPortalMetadata,
      lineage: lineage
    )
  }

  static func generatedInteger(
    _ value: Int32,
    lineage: VendorCharonStartLineage
  ) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: value,
      source: .generatedConstant,
      lineage: lineage
    )
  }

  static func generatedText(
    _ bytes: [UInt8],
    lineage: VendorCharonStartLineage
  ) -> VendorCharonStartTextValue {
    VendorCharonStartTextValue(
      value: PortalSP2ConstantTextMaterial(bytes),
      source: .generatedConstant,
      lineage: lineage
    )
  }

  static func strictInt32(
    _ scalar: PortalSP2Scalar,
    path: String
  ) throws -> Int32 {
    try scalar.withBytes { try strictInt32($0, path: path) }
  }

  static func strictInt32(
    _ bytes: UnsafeRawBufferPointer,
    path: String
  ) throws -> Int32 {
    guard !bytes.isEmpty else {
      throw AuthenticatedPortalSnapshotMappingError.invalidInteger(path)
    }
    var index = 0
    var negative = false
    if bytes[0] == 0x2d || bytes[0] == 0x2b {
      negative = bytes[0] == 0x2d
      index = 1
    }
    guard index < bytes.count else {
      throw AuthenticatedPortalSnapshotMappingError.invalidInteger(path)
    }
    var magnitude: Int64 = 0
    while index < bytes.count {
      let byte = bytes[index]
      guard (0x30...0x39).contains(byte) else {
        throw AuthenticatedPortalSnapshotMappingError.invalidInteger(path)
      }
      magnitude = magnitude * 10 + Int64(byte - 0x30)
      guard magnitude <= Int64(Int32.max) + (negative ? 1 : 0) else {
        throw AuthenticatedPortalSnapshotMappingError.invalidInteger(path)
      }
      index += 1
    }
    let signed = negative ? -magnitude : magnitude
    guard let result = Int32(exactly: signed) else {
      throw AuthenticatedPortalSnapshotMappingError.invalidInteger(path)
    }
    return result
  }
}
