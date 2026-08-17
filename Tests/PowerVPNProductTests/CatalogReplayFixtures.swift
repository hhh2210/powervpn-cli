import Foundation

@testable import PowerVPNPortal
@testable import PowerVPNProduct

/// Machine-readable provenance for one replay shape. Live catalog
/// rejections were recorded on 2026-08-12 / 2026-08-15 / 2026-08-16 with
/// the outcome token only — the finer classification was never recorded
/// for any live reject (schema-8 predates it; proxy mode dropped it).
/// Provenance therefore separates what was actually observed from what is
/// enumerated from the classification code, and never presents a
/// hypothesis as a conclusion.
enum CatalogReplayProvenance: String, Sendable, CaseIterable {
  /// Shape whose rejection outcome was recorded live. Because no live
  /// class was ever recorded, an `observed_live` entry is the dossier's
  /// designated best-fit stand-in for one specific recorded event, with
  /// the dossier row cited in `evidence`.
  case observedLive = "observed_live"
  /// Shape in the same structural family as an observed live rejection,
  /// but not itself the designated stand-in for any recorded event.
  case derivedFromObserved = "derived_from_observed"
  /// Shape enumerated from the failure-classification code to pin the
  /// taxonomy; never seen live.
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
  /// Fixture-internal byte sequences that must never reach a report.
  let sentinels: [String]
  /// Where this shape comes from; see `CatalogReplayProvenance`.
  let provenance: CatalogReplayProvenance
  /// Dossier row / classifier reference backing the provenance claim.
  /// Required for `.observedLive` and `.derivedFromObserved`.
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
    // Observed live (dossier-designated best-fit stand-ins).
    CatalogReplayShape(
      label: "catalog_empty",
      resourceXML: m2ResourceXML([]),
      expectedClass: .catalogEmpty,
      expectedFailure: nil,
      sentinels: [],
      provenance: .observedLive,
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
      sentinels: [],
      provenance: .observedLive,
      evidence:
        "catalog-investigation timeline row 21 (m2-live-attempt7 "
        + "2026-08-15, schema 8): resource_catalog_rejected recorded, "
        + "class not; resource_list_missing is the failure-hunter §6b "
        + "best-fit stand-in"
    ),
    // Same degraded-contentless-body family as the observed events.
    CatalogReplayShape(
      label: "integration_info_missing",
      resourceXML: replayXML(
        integrationInfo: nil,
        body: "<RESOURCE_LIST><NC_RESOURCE status=\"1\"/></RESOURCE_LIST>"
      ),
      expectedClass: .catalogMapping,
      expectedFailure: .scope(.integrationInfoMissing),
      sentinels: [],
      provenance: .derivedFromObserved,
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
      sentinels: [],
      provenance: .syntheticTaxonomy,
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
      sentinels: [],
      provenance: .syntheticTaxonomy,
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
      sentinels: [],
      provenance: .syntheticTaxonomy,
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
      sentinels: ["2x"],
      provenance: .syntheticTaxonomy,
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
      sentinels: ["0x1f4"],
      provenance: .syntheticTaxonomy,
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
      sentinels: [],
      provenance: .syntheticTaxonomy,
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
      sentinels: [],
      provenance: .syntheticTaxonomy,
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
      sentinels: ["duplicate-helper-session"],
      provenance: .syntheticTaxonomy,
      evidence: nil
    ),
  ]

  /// Fixture materials that must never leak into any report regardless of
  /// shape (session ids, key material, map ids are all synthetic bytes).
  static let universalSentinels = [
    "helper-session-material", "psk-material", "resource-map",
  ]

  /// Deterministic shape ordering for order-dependence replay. Seed 0 is
  /// the recorded order; seed n rotates the matrix by n. Seeds never come
  /// from randomness — CI selects them via `CATALOG_REPLAY_PERMUTATIONS`
  /// (comma-separated), default "0"; the nightly matrix passes one seed
  /// per matrix leg.
  static func order(seed: Int) -> [CatalogReplayShape] {
    guard !shapes.isEmpty else { return shapes }
    let offset = ((seed % shapes.count) + shapes.count) % shapes.count
    return Array(shapes[offset...] + shapes[..<offset])
  }

  static func permutationSeeds() -> [Int] {
    let raw =
      ProcessInfo.processInfo.environment["CATALOG_REPLAY_PERMUTATIONS"]
      ?? "0"
    return
      raw
      .split(separator: ",")
      .compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
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
