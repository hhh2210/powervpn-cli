import Foundation
import PowerVPNCore
import PowerVPNPortal

enum AuthenticatedPortalSnapshotMappingError: Error, Equatable, Sendable {
  case duplicateField(String)
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
