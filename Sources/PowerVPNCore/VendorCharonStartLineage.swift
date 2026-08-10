/// Opaque identity for one authenticated resource generation.
///
/// Construction is package-scoped so external callers cannot mint a lineage
/// token and claim that unrelated values share a source. Identity is compared
/// only with `===`; no stable or serializable identifier exists.
public final class VendorCharonStartLineage: @unchecked Sendable {
  package init() {}
}

public enum VendorCharonStartLineageStatus: String, Codable, Sendable {
  case missing
  case consistent
  case mixed
}
