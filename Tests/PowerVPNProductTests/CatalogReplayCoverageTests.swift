import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Coverage pins: the replay matrix must keep covering the full
/// server-reachable taxonomy, and every shape's provenance must stay
/// machine-readable and honest about what was observed live versus
/// enumerated from the classification code.
@Suite struct CatalogReplayCoverageTests {

  @Test func replayMatrixCoversTheServerReachableTaxonomy() {
    let covered = Set(
      CatalogReplayMatrix.shapes.compactMap { $0.expectedFailure?.failureClass })
    let expected: Set<ProductResourceCatalogFailureClass> = [
      .integrationInfoMissing, .resourceListMissing,
      .majorVersionMissing, .majorVersionDuplicate, .majorVersionMalformed,
      .majorVersionInvalid,
      .integerInvalid, .displayNameMissing, .displayNameInvalid, .duplicateField,
    ]
    #expect(covered == expected)
  }

  /// Classes unreachable from XML bytes at selection time are pinned to
  /// their existing coverage instead of the replay matrix:
  /// `resource_list_duplicate` is rejected by the snapshot-descriptor gate
  /// at mint time (acquisition stage, before any lease exists — asserted
  /// below), `material_too_large` by the bounded parser before mapping,
  /// `snapshot_inaccessible` is a client-lifecycle class, and scope
  /// `unclassified` is reachable only through opaque throws (no XML bytes
  /// produce it — pinned in `ProductPortalDryRunCatalogFailureTests`).
  @Test func duplicateResourceListIsRejectedAtMintBeforeAnyLease() {
    #expect(throws: AuthenticatedPortalSnapshotError.duplicateResourceList) {
      _ = try authenticatedSnapshot(
        resourceXML: "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/>"
          + "<RESOURCE_LIST/><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>")
    }
  }

  // MARK: provenance inventory

  /// Two coarse live outcomes (timeline rows 21 and 31) are associated with
  /// synthetic best-fit stand-ins. No live event recorded a concrete shape
  /// or classification, so the two provenance dimensions must never imply
  /// otherwise.
  @Test func provenanceInventoryIsPinnedAndEvidenceBacked() {
    let observedOutcomes = CatalogReplayMatrix.shapes.filter {
      $0.eventProvenance == .observedOutcome
    }
    let bestFits = CatalogReplayMatrix.shapes.filter {
      $0.shapeProvenance == .syntheticBestFit
    }
    let related = CatalogReplayMatrix.shapes.filter {
      $0.shapeProvenance == .syntheticRelated
    }
    #expect(observedOutcomes.count == 2)
    #expect(
      Set(observedOutcomes.map(\.label))
        == ["catalog_empty", "resource_list_missing"])
    #expect(Set(bestFits.map(\.label)) == Set(observedOutcomes.map(\.label)))
    for shape in bestFits {
      #expect(shape.eventProvenance == .observedOutcome)
    }
    for shape in related {
      #expect(shape.eventProvenance == .noObservedEvent)
    }
    for shape in bestFits + related {
      #expect(
        !(shape.evidence?.isEmpty ?? true),
        "\(shape.label) must cite dossier evidence")
    }
    for shape in CatalogReplayMatrix.shapes
    where
      shape.shapeProvenance == .syntheticTaxonomy
    {
      #expect(shape.eventProvenance == .noObservedEvent)
      #expect(shape.evidence == nil, "\(shape.label) must not claim evidence")
    }
  }

  @Test func sentinelInventoryPinsRawFailuresAndUniqueSnapshotSessions() {
    let expectedRawValues: [String: Set<String>] = [
      "major_version_invalid": ["2x"],
      "resource_integer_invalid_ike_port": ["0x1f4"],
      "resource_display_name_invalid": [String(repeating: "a", count: 257)],
      "resource_duplicate_field": ["duplicate-helper-session"],
    ]

    for shape in CatalogReplayMatrix.shapes {
      let expected = expectedRawValues[shape.label] ?? []
      #expect(Set(shape.rawFailureValues) == expected)
      for rawValue in shape.rawFailureValues {
        #expect(shape.resourceXML.contains(rawValue))
      }
    }

    let snapshotSessions = CatalogReplayMatrix.shapeIDs.flatMap {
      CatalogReplayMatrix.snapshotSentinels(shapeID: $0)
    }
    #expect(snapshotSessions.count == CatalogReplayMatrix.shapeIDs.count * 3)
    #expect(Set(snapshotSessions).count == snapshotSessions.count)
    #expect(CatalogReplayMatrix.universalSentinels.contains("cookie-session-material"))
  }
}
