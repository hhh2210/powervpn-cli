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
    var minted = false
    do {
      _ = try authenticatedSnapshot(
        resourceXML: "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/>"
          + "<RESOURCE_LIST/><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>")
      minted = true
    } catch {}
    #expect(!minted, "duplicate RESOURCE_LIST must be rejected by the mint gate")
  }

  // MARK: provenance inventory

  /// Exactly one dossier-designated stand-in per recorded live catalog
  /// rejection (timeline rows 21 and 31); every observed/derived shape
  /// must cite its evidence. No live classification was ever recorded, so
  /// `observed_live` claims are stand-ins by construction — the pinned
  /// count keeps that honest.
  @Test func provenanceInventoryIsPinnedAndEvidenceBacked() {
    let observed = CatalogReplayMatrix.shapes.filter { $0.provenance == .observedLive }
    let derived = CatalogReplayMatrix.shapes.filter {
      $0.provenance == .derivedFromObserved
    }
    #expect(observed.count == 2)
    #expect(Set(observed.map(\.label)) == ["catalog_empty", "resource_list_missing"])
    for shape in observed + derived {
      #expect(
        !(shape.evidence?.isEmpty ?? true),
        "\(shape.label) must cite dossier evidence")
    }
    for shape in CatalogReplayMatrix.shapes
    where
      shape.provenance == .syntheticTaxonomy
    {
      #expect(shape.evidence == nil, "\(shape.label) must not claim evidence")
    }
  }
}
