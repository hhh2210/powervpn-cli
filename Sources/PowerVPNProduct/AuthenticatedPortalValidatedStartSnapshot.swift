import Foundation
import PowerVPNCore
import PowerVPNPortal

package enum AuthenticatedPortalValidatedSnapshotError: Error, Equatable, Sendable {
  case invalidResourceHandle
  case resourceGenerationMismatch
  case resourceNotFound
  case incompleteSnapshot(VendorCharonStartField?)
}

extension AuthenticatedPortalSnapshotMapper {
  package static func withValidatedStartSnapshot(
    _ snapshot: AuthenticatedPortalSnapshot,
    handle: String,
    _ body: (VendorCharonStartSnapshot) throws -> Void
  ) throws {
    let index = try authenticatedPortalResourceIndex(
      handle,
      expectedGeneration: snapshot.selectionGenerationID
    )
    try withAuthenticatedPortalSP2MappingScope(
      snapshot
    ) { gateway, majorVersion, resources in
      guard resources.indices.contains(index) else {
        throw AuthenticatedPortalValidatedSnapshotError.resourceNotFound
      }
      let (_, validation) = try AuthenticatedPortalSP2Mapper.validatedCandidate(
        resources[index],
        handle: handle,
        majorVersion: majorVersion,
        gateway: gateway
      )
      guard let startSnapshot = validation.snapshot else {
        throw AuthenticatedPortalValidatedSnapshotError.incompleteSnapshot(
          validation.firstMissingField
        )
      }
      try body(startSnapshot)
    }
  }
}

func authenticatedPortalResourceHandle(
  _ snapshot: AuthenticatedPortalSnapshot,
  index: Int
) -> String {
  "portal:\(snapshot.selectionGenerationID.uuidString.lowercased()):nc:\(index)"
}

private func authenticatedPortalResourceIndex(
  _ handle: String,
  expectedGeneration: UUID
) throws -> Int {
  let components = handle.split(separator: ":", omittingEmptySubsequences: false)
  guard components.count == 4,
    components[0] == "portal",
    components[2] == "nc",
    let generation = UUID(uuidString: String(components[1])),
    components[1] == Substring(generation.uuidString.lowercased()),
    let index = Int(components[3]),
    index >= 0,
    String(index) == components[3]
  else {
    throw AuthenticatedPortalValidatedSnapshotError.invalidResourceHandle
  }
  guard components[1] == Substring(expectedGeneration.uuidString.lowercased()) else {
    throw AuthenticatedPortalValidatedSnapshotError.resourceGenerationMismatch
  }
  return index
}
