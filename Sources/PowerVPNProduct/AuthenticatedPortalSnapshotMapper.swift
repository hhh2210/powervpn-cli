import Foundation
import PowerVPNCore
import PowerVPNPortal

enum AuthenticatedPortalSnapshotMappingError: Error, Equatable, Sendable {
  case duplicateField(String)
  /// The `NC_RESOURCE` has no `TUNNEL` child at all.
  case missingTunnelElement
  /// The first `TUNNEL` has no `tunnel-name` attribute.
  case missingDisplayName
  case invalidDisplayName
  case invalidInteger(String)
  case materialTooLarge
}

/// Maps one authenticated Portal generation into value-free Core readiness.
///
/// Only statically proven SP2 mappings are promoted. In particular, helper
/// `common.sessionid` comes from `TUNNEL.IKE.CLIENT.id`; the Portal cookie is
/// deliberately inaccessible here. Every returned candidate belongs to one
/// `NC_RESOURCE` and sibling resources are never unioned.
package enum AuthenticatedPortalSnapshotMapper {
  static func map(
    _ snapshot: AuthenticatedPortalSnapshot
  ) throws -> [ProductResourceCandidate] {
    try withAuthenticatedPortalSP2MappingScope(snapshot) { gateway, majorVersion, resources in
      try resources.enumerated().map { index, resource in
        try AuthenticatedPortalSP2Mapper.candidate(
          resource,
          handle: authenticatedPortalResourceHandle(snapshot, index: index),
          majorVersion: majorVersion,
          gateway: gateway
        )
      }
    }
  }
}

extension AuthenticatedPortalSnapshotMapper {
  /// Catalog mapping with value-free failure classification for diagnostics.
  ///
  /// On success returns the candidates and no failure. On failure returns no
  /// candidates plus a `ProductResourceCatalogFailure`: scope-stage failures
  /// (INTERGRATION_INFO, RESOURCE_LIST, VERSION@major) carry no ordinal;
  /// per-resource failures carry the failing entry's one-based ordinal and a
  /// structural field-path token. Never throws and never retains values.
  package static func mapClassified(
    _ snapshot: AuthenticatedPortalSnapshot
  ) -> (candidates: [ProductResourceCandidate], failure: ProductResourceCatalogFailure?) {
    do {
      let candidates: [ProductResourceCandidate] =
        try withAuthenticatedPortalSP2MappingScope(snapshot) {
          gateway, majorVersion, resources in
          try resources.indices.map { index in
            do {
              return try AuthenticatedPortalSP2Mapper.candidate(
                resources[index],
                handle: authenticatedPortalResourceHandle(snapshot, index: index),
                majorVersion: majorVersion,
                gateway: gateway
              )
            } catch let error as AuthenticatedPortalSnapshotMappingError {
              throw AuthenticatedPortalResourceCatalogDiagnostic(
                resourceOrdinal: index + 1,
                mappingError: error
              )
            }
          }
        }
      return (candidates, nil)
    } catch let diagnostic as AuthenticatedPortalResourceCatalogDiagnostic {
      return ([], diagnostic.failure)
    } catch {
      return (
        [],
        AuthenticatedPortalResourceCatalogDiagnostic(
          classifyingScopeError: error
        ).failure
      )
    }
  }
}
