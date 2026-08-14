import PowerVPNPortal

/// Typed, value-free classification of one catalog-mapping failure.
///
/// The diagnostic carries only the report-shaped failure (stage, closed
/// failure class, one-based `NC_RESOURCE` ordinal, structural field-path
/// token). No Portal response bytes, display names, or values of any kind are
/// retained, so it is safe to surface in JSON reports.
package struct AuthenticatedPortalResourceCatalogDiagnostic: Error, Equatable,
  Sendable
{
  package let failure: ProductResourceCatalogFailure

  private init(failure: ProductResourceCatalogFailure) {
    self.failure = failure
  }

  /// Classifies a per-resource mapping failure of the entry at `ordinal`
  init(
    resourceOrdinal: Int,
    mappingError: AuthenticatedPortalSnapshotMappingError
  ) {
    let failureClass: ProductResourceCatalogFailureClass
    var fieldPath: String?
    switch mappingError {
    case .duplicateField(let name):
      failureClass = .duplicateField
      fieldPath = name
    case .missingTunnelElement:
      failureClass = .displayNameMissing
      fieldPath = "TUNNEL"
    case .missingDisplayName:
      failureClass = .displayNameMissing
      fieldPath = "TUNNEL.tunnel-name"
    case .invalidDisplayName:
      failureClass = .displayNameInvalid
      fieldPath = "TUNNEL.tunnel-name"
    case .invalidInteger(let path):
      failureClass = .integerInvalid
      fieldPath = path
    case .materialTooLarge:
      failureClass = .materialTooLarge
    }
    failure = ProductResourceCatalogFailure(
      stage: .resource,
      failureClass: failureClass,
      resourceOrdinal: resourceOrdinal,
      fieldPath: fieldPath
    )
  }

  /// Classifies any error thrown while borrowing the mapping scope
  /// (INTERGRATION_INFO context, RESOURCE_LIST, VERSION@major). Errors that
  /// are opaque outside PowerVPNPortal stay total and value-free as
  /// `.unclassified`.
  package init(classifyingScopeError error: any Error) {
    if let snapshotError = error as? AuthenticatedPortalSnapshotError {
      switch snapshotError {
      case .erased, .inaccessible, .inactiveAuthenticationGeneration:
        self.init(failure: Self.scopeFailure(.snapshotInaccessible))
      case .missingResourceList:
        self.init(failure: Self.scopeFailure(.resourceListMissing))
      case .duplicateResourceList:
        self.init(failure: Self.scopeFailure(.resourceListDuplicate))
      }
      return
    }
    if let contextError = error as? AuthenticatedPortalContextBorrowError {
      switch contextError {
      case .expired:
        self.init(failure: Self.scopeFailure(.snapshotInaccessible))
      case .missingIntegrationInfo:
        self.init(failure: Self.scopeFailure(.integrationInfoMissing))
      case .missingVersion, .missingMajorVersion:
        self.init(failure: Self.scopeFailure(.majorVersionMissing))
      case .duplicateVersion:
        self.init(failure: Self.scopeFailure(.majorVersionDuplicate))
      case .malformedMajorVersion:
        self.init(failure: Self.scopeFailure(.majorVersionMalformed))
      }
      return
    }
    if let borrowError = error as? AuthenticatedPortalResourceBorrowError {
      switch borrowError {
      case .expired:
        self.init(failure: Self.scopeFailure(.snapshotInaccessible))
      case .notScalar, .missingAttribute:
        self.init(failure: Self.scopeFailure(.unclassified))
      }
      return
    }
    if let mappingError = error as? AuthenticatedPortalSnapshotMappingError,
      case .invalidInteger = mappingError
    {
      // The only strict-decimal-integer parse at scope stage is
      // VERSION@major.
      self.init(
        failure: Self.scopeFailure(
          .majorVersionInvalid,
          fieldPath: "common.majorVersion"
        )
      )
      return
    }
    self.init(failure: Self.scopeFailure(.unclassified))
  }

  private static func scopeFailure(
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
