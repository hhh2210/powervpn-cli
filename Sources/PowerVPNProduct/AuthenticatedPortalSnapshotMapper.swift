import Foundation
import PowerVPNCore
import PowerVPNPortal

enum AuthenticatedPortalSnapshotMappingError: Error, Equatable, Sendable {
  case duplicateField(String)
  case invalidDisplayName
}

/// Maps one authenticated Portal generation into value-free Core readiness.
///
/// Only statically proven SP2 mappings are promoted. In particular, helper
/// `common.sessionid` comes from `TUNNEL.IKE.CLIENT.id`; the Portal cookie is
/// deliberately inaccessible here. Every returned candidate belongs to one
/// `NC_RESOURCE` and sibling resources are never unioned.
enum AuthenticatedPortalSnapshotMapper {
  static func map(
    _ snapshot: AuthenticatedPortalSnapshot
  ) throws -> [ProductResourceCandidate] {
    try snapshot.withResourceTree { resourceList in
      try resourceList.childElements
        .filter { $0.name == AuthenticatedPortalResourceCategory.networkConnect.rawValue }
        .enumerated()
        .map { index, resource in
          try candidate(
            resource,
            handle: "portal:\(snapshot.selectionGenerationID.uuidString.lowercased()):nc:\(index)"
          )
        }
    }
  }

  private static func candidate(
    _ resource: AuthenticatedPortalResourceElement,
    handle: String
  ) throws -> ProductResourceCandidate {
    let displayName = try resourceDisplayName(resource)
    let lineage = VendorCharonStartLineage()
    let sessionID = try optionalDescendant(
      from: resource,
      path: ["TUNNEL", "IKE", "CLIENT", "id"]
    ).map { element -> VendorCharonStartTextValue in
      let material = try BorrowedPortalTextMaterial(element)
      return VendorCharonStartTextValue(
        value: material,
        source: .authenticatedPortalResource,
        lineage: lineage
      )
    }
    let coreCandidate = VendorCharonStartCandidate(
      lineage: lineage,
      common: VendorCharonStartCommonCandidate(sessionID: sessionID),
      tunnels: nil
    )
    return ProductResourceCandidate(
      summary: ProductResourceSummary(handle: handle, displayName: displayName),
      validation: VendorCharonStartValidator.validate(coreCandidate)
    )
  }

  /// `NC_RESOURCE/name` is the sole Portal scalar intentionally promoted to a
  /// retained Product value. It is authorized catalog metadata for selection,
  /// never helper material, and remains bound to an opaque generation handle.
  private static func resourceDisplayName(
    _ resource: AuthenticatedPortalResourceElement
  ) throws -> String {
    guard let element = try optionalChild(named: "name", of: resource) else {
      throw AuthenticatedPortalSnapshotMappingError.invalidDisplayName
    }
    var result: String?
    try element.withScalarBytes { bytes in
      guard (1...256).contains(bytes.count), !bytes.contains(0),
        let value = String(bytes: bytes, encoding: .utf8),
        value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
      else {
        throw AuthenticatedPortalSnapshotMappingError.invalidDisplayName
      }
      result = value
    }
    guard let result else {
      throw AuthenticatedPortalSnapshotMappingError.invalidDisplayName
    }
    return result
  }

  private static func optionalDescendant(
    from root: AuthenticatedPortalResourceElement,
    path: [String]
  ) throws -> AuthenticatedPortalResourceElement? {
    var current: AuthenticatedPortalResourceElement? = root
    for name in path {
      guard let element = current else { return nil }
      current = try optionalChild(named: name, of: element)
    }
    return current
  }

  private static func optionalChild(
    named name: String,
    of parent: AuthenticatedPortalResourceElement
  ) throws -> AuthenticatedPortalResourceElement? {
    let matches = try parent.childElements.filter { $0.name == name }
    guard matches.count <= 1 else {
      throw AuthenticatedPortalSnapshotMappingError.duplicateField(name)
    }
    return matches.first
  }
}

private struct BorrowedPortalTextMaterial: VendorCharonStartTextMaterial {
  let byteCount: Int
  private let element: AuthenticatedPortalResourceElement

  init(_ element: AuthenticatedPortalResourceElement) throws {
    self.element = element
    byteCount = try element.withScalarBytes(\.count)
  }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try element.withScalarBytes(body)
  }
}
