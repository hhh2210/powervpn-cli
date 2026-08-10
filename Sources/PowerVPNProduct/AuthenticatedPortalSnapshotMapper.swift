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
enum AuthenticatedPortalSnapshotMapper {
  static func map(
    _ snapshot: AuthenticatedPortalSnapshot
  ) throws -> [ProductResourceCandidate] {
    try snapshot.withPortalContext { context in
      try context.withMajorVersionBytes { majorBytes in
        let majorVersion = try PortalSP2Value.strictInt32(
          majorBytes,
          path: "common.majorVersion"
        )
        return try snapshot.withResourceTree { resourceList in
          try resourceList.childElements
            .filter { $0.name == AuthenticatedPortalResourceCategory.networkConnect.rawValue }
            .enumerated()
            .map { index, resource in
              try AuthenticatedPortalSP2Mapper.candidate(
                resource,
                handle:
                  "portal:\(snapshot.selectionGenerationID.uuidString.lowercased()):nc:\(index)",
                majorVersion: majorVersion
              )
            }
        }
      }
    }
  }
}
