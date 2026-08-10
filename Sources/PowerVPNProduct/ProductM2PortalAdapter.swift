import PowerVPNCore
import PowerVPNPortal

package struct ProductM2PortalAdapter: ProductM2AuthorizedResourceProviding {
  package typealias AcquirePortal = @Sendable () async -> PortalSnapshotAcquisitionResult

  package let source = ProductM2AuthorizationSource.nativePortal
  package let availabilityFailure: ProductM2AuthorizationFailure? = nil
  private let acquirePortal: AcquirePortal

  package init(
    acquirePortal: @escaping AcquirePortal = PortalLoginRuntime.acquireCurrentMachine
  ) {
    self.acquirePortal = acquirePortal
  }

  package func acquire() async -> ProductM2AuthorizedResourceAcquisition {
    switch await acquirePortal() {
    case .acquired(let portalLease):
      return .acquired(
        source: source,
        lease: Self.authorizationLease(portalLease),
        serverContactRequested: true
      )
    case .rejected(let report):
      let operations = report.operations
      return .rejected(
        source: source,
        failure: ProductM2AuthorizationFailure(report.status),
        cleanup: ProductM2AuthorizationCloseReceipt(
          outcome: operations.loginAccepted
            ? (operations.logoutRequested && operations.logoutAccepted
              ? .accepted : .rejected)
            : .notRequired,
          ownedMaterialErased: report.operationsOwnedMaterialErased,
          sourceCloseRequested: operations.logoutRequested,
          serverContactRequested: operations.loginRequested
            || operations.sessionCheckRequested
            || operations.resourceListRequested
            || operations.logoutRequested
        )
      )
    }
  }

  package static func acquireCurrentMachine() async -> ProductM2AuthorizedResourceAcquisition {
    await Self().acquire()
  }

  private static func authorizationLease(
    _ portalLease: AuthenticatedPortalLease
  ) -> ProductM2AuthorizedResourceLease {
    ProductM2AuthorizedResourceLease(
      source: .nativePortal,
      catalog: {
        try catalog(snapshot: portalLease.snapshot)
      },
      prepare: { handle, requiredTargetIPv4 in
        try prepare(
          snapshot: portalLease.snapshot,
          handle: handle,
          requiredTargetIPv4: requiredTargetIPv4
        )
      },
      eraseOwnedMaterial: {
        portalLease.snapshot.erase()
        return portalLease.snapshot.isErased
      },
      close: {
        let status = await portalLease.logoutAndErase()
        return ProductM2AuthorizationCloseReceipt(
          outcome: ProductM2AuthorizationCloseOutcome(status),
          ownedMaterialErased: portalLease.snapshot.isErased,
          sourceCloseRequested: status != .alreadyClosed,
          serverContactRequested: status != .alreadyClosed
        )
      }
    )
  }

  package static func prepare(
    snapshot: AuthenticatedPortalSnapshot,
    handle: String,
    requiredTargetIPv4: UInt32
  ) throws -> ProductM2PreparedAuthorizedResource {
    let candidates: [ProductResourceCandidate]
    do {
      candidates = try AuthenticatedPortalSnapshotMapper.map(snapshot)
        .filter { $0.summary.handle == handle }
    } catch {
      throw ProductM2AuthorizedResourceSelectionError.catalogRejected
    }
    guard candidates.count == 1 else {
      throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
    }
    let candidate = candidates[0]
    let lineage = VendorCharonStartLineage()

    var matcher: VendorCharonSelectedRouteMatcher?
    do {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        snapshot,
        handle: handle,
        lineage: lineage
      ) { startSnapshot in
        matcher = try startSnapshot.makeSelectedRouteMatcher(
          requiredTargetIPv4: requiredTargetIPv4
        )
      }
    } catch VendorCharonSelectedRouteMatcherError.requiredTargetNotCovered {
      throw ProductM2AuthorizedResourceSelectionError.selectedRouteCoverageRejected
    } catch {
      throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
    }
    guard let matcher else {
      throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
    }

    return ProductM2PreparedAuthorizedResource(
      summary: candidate.summary,
      selectedRoutes: matcher,
      requiredTargetIPv4: requiredTargetIPv4,
      withStartSnapshot: { body in
        try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
          snapshot,
          handle: handle,
          lineage: lineage
        ) { startSnapshot in
          try body(startSnapshot)
        }
      }
    )
  }

  package static func catalog(
    snapshot: AuthenticatedPortalSnapshot
  ) throws -> [ProductResourceCandidate] {
    do {
      return try AuthenticatedPortalSnapshotMapper.map(snapshot)
    } catch {
      throw ProductM2AuthorizedResourceSelectionError.catalogRejected
    }
  }
}

extension PortalLoginReport {
  fileprivate var operationsOwnedMaterialErased: Bool {
    ownedMaterial.credentialsErased
      && ownedMaterial.requestBodiesErased
      && ownedMaterial.responseBodiesErased
      && ownedMaterial.sessionMaterialErased
  }
}

extension ProductM2AuthorizationFailure {
  init(_ status: PortalLoginStatus) {
    switch status {
    case .accepted: self = .accepted
    case .configurationRejected: self = .configurationRejected
    case .credentialInputRejected: self = .credentialInputRejected
    case .transportRejected: self = .transportRejected
    case .tlsRejected: self = .tlsRejected
    case .redirectRejected: self = .redirectRejected
    case .loginRejected: self = .loginRejected
    case .challengeRequired: self = .challengeRequired
    case .loginResponseRejected: self = .loginResponseRejected
    case .sessionRejected: self = .sessionRejected
    case .resourceListRejected: self = .resourceListRejected
    case .authenticatedSnapshotRejected: self = .authenticatedSnapshotRejected
    case .logoutRejected: self = .logoutRejected
    case .cancelled: self = .cancelled
    case .internalFailure: self = .internalFailure
    }
  }
}

extension ProductM2AuthorizationCloseOutcome {
  init(_ status: PortalLeaseLogoutStatus) {
    switch status {
    case .accepted: self = .accepted
    case .rejected: self = .rejected
    case .timedOut: self = .timedOut
    case .cancelled: self = .cancelled
    case .alreadyClosed: self = .alreadyClosed
    }
  }
}
