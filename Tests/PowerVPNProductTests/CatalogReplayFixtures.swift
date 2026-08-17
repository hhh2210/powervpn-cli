import Foundation

@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Whether a live event outcome exists behind a fixture. Live events only
/// recorded the coarse `resource_catalog_rejected` outcome; none captured
/// the XML shape or fine-grained classification used by this replay.
enum CatalogReplayEventProvenance: String, Sendable, CaseIterable {
  case observedOutcome = "observed_outcome"
  case noObservedEvent = "no_observed_event"
}

/// Where the concrete XML/classification pair came from. Every replay shape
/// is synthetic, including best-fit stand-ins associated with live outcomes.
enum CatalogReplayShapeProvenance: String, Sendable, CaseIterable {
  case syntheticBestFit = "synthetic_best_fit"
  case syntheticRelated = "synthetic_related"
  case syntheticTaxonomy = "synthetic_taxonomy"
}

/// One server-behavior shape for deterministic offline replay: an
/// accepted password login whose resource-list reply then fails catalog
/// mapping. Value-free by construction: synthetic XML only, RFC 5737 /
/// RFC 1918 documentation addresses, closed tokens, no intranet values.
struct CatalogReplayShape: Sendable {
  /// Closed-form label used in test names (`catalog_replay_<label>`).
  let label: String
  /// Synthetic resource-list XML the "server" returns for this shape.
  let resourceXML: String
  /// The classification the first selection attempt must report.
  let expectedClass: ProductM2SelectionFailureClass
  /// The catalog-mapping detail the first selection attempt must report
  /// (`nil` for `catalog_empty`, which carries the class only).
  let expectedFailure: ProductResourceCatalogFailure?
  /// Raw failure-causing byte sequences that must never reach a report.
  let rawFailureValues: [String]
  /// Whether a coarse live outcome is associated with this synthetic shape.
  let eventProvenance: CatalogReplayEventProvenance
  /// Where the concrete synthetic XML/classification pair came from.
  let shapeProvenance: CatalogReplayShapeProvenance
  /// Dossier row or classifier reference backing the association claim.
  /// Required for best-fit/related shapes; absent for taxonomy-only shapes.
  let evidence: String?
}

/// Every catalog-rejection shape reachable from XML bytes at selection
/// time. Coverage holes are pinned in `CatalogReplayCoverageTests`:
/// `resource_list_duplicate` is rejected by the snapshot-descriptor gate
/// at mint time (before any lease exists), `material_too_large` by the
/// bounded XML parser before mapping runs, and scope `unclassified` is
/// reachable only through opaque throws (no XML bytes produce it).
enum CatalogReplayMatrix {
  static let requestedDisplayName = "Campus NC"

  static let shapes: [CatalogReplayShape] = [
    // Synthetic best-fit stand-ins associated with observed coarse outcomes.
    CatalogReplayShape(
      label: "catalog_empty",
      resourceXML: m2ResourceXML([]),
      expectedClass: .catalogEmpty,
      expectedFailure: nil,
      rawFailureValues: [],
      eventProvenance: .observedOutcome,
      shapeProvenance: .syntheticBestFit,
      evidence:
        "catalog-investigation timeline row 31 (proxy-ssh-4-ide "
        + "2026-08-16): resource_catalog_rejected recorded, class not; "
        + "catalog_empty is the failure-hunter §6b best-fit stand-in"
    ),
    CatalogReplayShape(
      label: "resource_list_missing",
      resourceXML: "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/>"
        + "</INTERGRATION_INFO></ROOT>",
      expectedClass: .catalogMapping,
      expectedFailure: .scope(.resourceListMissing),
      rawFailureValues: [],
      eventProvenance: .observedOutcome,
      shapeProvenance: .syntheticBestFit,
      evidence:
        "catalog-investigation timeline row 21 (m2-live-attempt7 "
        + "2026-08-15, schema 8): resource_catalog_rejected recorded, "
        + "class not; resource_list_missing is the failure-hunter §6b "
        + "best-fit stand-in"
    ),
    // Synthetic sibling hypothesis from failure-hunter; no matching live event.
    CatalogReplayShape(
      label: "integration_info_missing",
      resourceXML: replayXML(
        integrationInfo: nil,
        body: "<RESOURCE_LIST><NC_RESOURCE status=\"1\"/></RESOURCE_LIST>"
      ),
      expectedClass: .catalogMapping,
      expectedFailure: .scope(.integrationInfoMissing),
      rawFailureValues: [],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticRelated,
      evidence: "failure-hunter §3 row 2: 200 XML reply with no INTERGRATION_INFO"
    ),
    // Enumerated from the classification code; never seen live.
    CatalogReplayShape(
      label: "major_version_missing",
      resourceXML: replayXML(
        integrationInfo: "<INTERGRATION_INFO>",
        body: "<RESOURCE_LIST><NC_RESOURCE status=\"1\"/></RESOURCE_LIST>"
          + "</INTERGRATION_INFO>"
      ),
      expectedClass: .catalogMapping,
      expectedFailure: .scope(.majorVersionMissing),
      rawFailureValues: [],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "major_version_duplicate",
      resourceXML: replayXML(
        integrationInfo: "<INTERGRATION_INFO><VERSION major=\"2\"/>"
          + "<VERSION major=\"2\"/>",
        body: "<RESOURCE_LIST><NC_RESOURCE status=\"1\"/></RESOURCE_LIST>"
          + "</INTERGRATION_INFO>"
      ),
      expectedClass: .catalogMapping,
      expectedFailure: .scope(.majorVersionDuplicate),
      rawFailureValues: [],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "major_version_malformed",
      resourceXML: replayXML(
        integrationInfo: "<INTERGRATION_INFO><VERSION><major>2</major></VERSION>",
        body: "<RESOURCE_LIST><NC_RESOURCE status=\"1\"/></RESOURCE_LIST>"
          + "</INTERGRATION_INFO>"
      ),
      expectedClass: .catalogMapping,
      expectedFailure: .scope(.majorVersionMalformed),
      rawFailureValues: [],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "major_version_invalid",
      resourceXML: replayXML(
        integrationInfo: "<INTERGRATION_INFO><VERSION major=\"2x\"/>",
        body: "<RESOURCE_LIST><NC_RESOURCE status=\"1\"/></RESOURCE_LIST>"
          + "</INTERGRATION_INFO>"
      ),
      expectedClass: .catalogMapping,
      expectedFailure: .init(
        stage: .scope, failureClass: .majorVersionInvalid,
        resourceOrdinal: nil, fieldPath: "common.majorVersion"
      ),
      rawFailureValues: ["2x"],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "resource_integer_invalid_ike_port",
      resourceXML: m2ResourceXML([requestedDisplayName])
        .replacingOccurrences(of: "port=\"500\"", with: "port=\"0x1f4\""),
      expectedClass: .catalogMapping,
      expectedFailure: .init(
        stage: .resource, failureClass: .integerInvalid,
        resourceOrdinal: 1, fieldPath: "common.ike_port"
      ),
      rawFailureValues: ["0x1f4"],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "resource_display_name_missing",
      resourceXML: m2ResourceXML([requestedDisplayName])
        .replacingOccurrences(
          of: "<TUNNEL tunnel-name=\"\(requestedDisplayName)\"",
          with: "<TUNNEL"
        ),
      expectedClass: .catalogMapping,
      expectedFailure: .init(
        stage: .resource, failureClass: .displayNameMissing,
        resourceOrdinal: 1, fieldPath: "TUNNEL.tunnel-name"
      ),
      rawFailureValues: [],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "resource_display_name_invalid",
      resourceXML: m2ResourceXML([String(repeating: "a", count: 257)]),
      expectedClass: .catalogMapping,
      expectedFailure: .init(
        stage: .resource, failureClass: .displayNameInvalid,
        resourceOrdinal: 1, fieldPath: "TUNNEL.tunnel-name"
      ),
      rawFailureValues: [String(repeating: "a", count: 257)],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
    CatalogReplayShape(
      label: "resource_duplicate_field",
      resourceXML: m2ResourceXML([requestedDisplayName])
        .replacingOccurrences(
          of: "<CLIENT id=\"helper-session-material\"/>",
          with: "<CLIENT id=\"helper-session-material\">"
            + "<id>duplicate-helper-session</id></CLIENT>"
        ),
      expectedClass: .catalogMapping,
      expectedFailure: .init(
        stage: .resource, failureClass: .duplicateField,
        resourceOrdinal: 1, fieldPath: "id"
      ),
      rawFailureValues: ["duplicate-helper-session"],
      eventProvenance: .noObservedEvent,
      shapeProvenance: .syntheticTaxonomy,
      evidence: nil
    ),
  ]

  /// Fixture materials that must never leak into any report regardless of
  /// shape (session ids, key material, map ids are all synthetic bytes).
  static let universalSentinels = [
    "helper-session-material", "psk-material", "resource-map",
    "cookie-session-material",
  ]

  static let shapeIDs = shapes.map(\.label)

  static func shape(id: String) -> CatalogReplayShape? {
    shapes.first { $0.label == id }
  }

  static func snapshotCookie(shapeID: String, attempt: String) -> String {
    "catalog-replay-\(shapeID)-\(attempt)-cookie"
  }

  static func snapshotSentinels(shapeID: String) -> [String] {
    ["first", "retry", "support"].map {
      snapshotCookie(shapeID: shapeID, attempt: $0)
    }
  }

  private static func replayXML(integrationInfo: String?, body: String) -> String {
    "<ROOT>" + (integrationInfo ?? "") + body + "</ROOT>"
  }
}

extension ProductResourceCatalogFailure {
  /// Scope-stage fixture shorthand (ordinal and field path are nil unless
  /// a field path is pinned).
  static func scope(
    _ failureClass: ProductResourceCatalogFailureClass,
    fieldPath: String? = nil
  ) -> ProductResourceCatalogFailure {
    ProductResourceCatalogFailure(
      stage: .scope,
      failureClass: failureClass,
      resourceOrdinal: nil,
      fieldPath: fieldPath
    )
  }
}
