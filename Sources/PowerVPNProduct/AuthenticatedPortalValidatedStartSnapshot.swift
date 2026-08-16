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
    lineage: VendorCharonStartLineage = VendorCharonStartLineage(),
    _ body: (VendorCharonStartSnapshot) throws -> Void
  ) throws {
    let selection = try authenticatedPortalResourceSelection(
      handle,
      expectedGeneration: snapshot.selectionGenerationID
    )
    try withAuthenticatedPortalSP2MappingScope(
      snapshot
    ) { gateway, majorVersion, resources in
      guard resources.indices.contains(selection.sourceResourceIndex) else {
        throw AuthenticatedPortalValidatedSnapshotError.resourceNotFound
      }
      let mapped = try AuthenticatedPortalSP2Mapper.mappedResource(
        resources[selection.sourceResourceIndex],
        majorVersion: majorVersion,
        gateway: gateway,
        lineage: lineage
      )
      guard
        let descriptor = mapped.tunnels.first(where: {
          $0.sourceTunnelIndex == selection.sourceTunnelIndex
        })
      else {
        throw AuthenticatedPortalValidatedSnapshotError.resourceNotFound
      }
      guard let startSnapshot = mapped.validation.snapshot else {
        throw AuthenticatedPortalValidatedSnapshotError.incompleteSnapshot(
          mapped.validation.firstMissingField
        )
      }
      guard
        let selectedSnapshot = startSnapshot.selectingTunnel(
          atEncodedIndex: descriptor.encodedTunnelIndex
        )
      else {
        throw AuthenticatedPortalValidatedSnapshotError.resourceNotFound
      }
      try body(selectedSnapshot)
    }
  }
}

func authenticatedPortalResourceHandle(
  _ snapshot: AuthenticatedPortalSnapshot,
  resourceIndex: Int,
  sourceTunnelIndex: Int
) -> String {
  "portal:\(snapshot.selectionGenerationID.uuidString.lowercased())"
    + ":nc:\(resourceIndex):tunnel:\(sourceTunnelIndex)"
}

private struct AuthenticatedPortalResourceSelection {
  let sourceResourceIndex: Int
  let sourceTunnelIndex: Int
}

private func authenticatedPortalResourceSelection(
  _ handle: String,
  expectedGeneration: UUID
) throws -> AuthenticatedPortalResourceSelection {
  let components = handle.split(separator: ":", omittingEmptySubsequences: false)
  guard components.count == 6,
    components[0] == "portal",
    components[2] == "nc",
    components[4] == "tunnel",
    let generation = UUID(uuidString: String(components[1])),
    components[1] == Substring(generation.uuidString.lowercased()),
    let resourceIndex = Int(components[3]),
    resourceIndex >= 0,
    String(resourceIndex) == components[3],
    let tunnelIndex = Int(components[5]),
    tunnelIndex >= 0,
    String(tunnelIndex) == components[5]
  else {
    throw AuthenticatedPortalValidatedSnapshotError.invalidResourceHandle
  }
  guard components[1] == Substring(expectedGeneration.uuidString.lowercased()) else {
    throw AuthenticatedPortalValidatedSnapshotError.resourceGenerationMismatch
  }
  return AuthenticatedPortalResourceSelection(
    sourceResourceIndex: resourceIndex,
    sourceTunnelIndex: tunnelIndex
  )
}
