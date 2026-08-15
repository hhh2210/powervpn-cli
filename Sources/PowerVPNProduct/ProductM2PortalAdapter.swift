import Foundation
import PowerVPNCore
import PowerVPNPortal

package struct ProductM2PortalAdapter: ProductM2AuthorizedResourceProviding {
  package typealias AcquirePortal =
    @Sendable (ProductM2AuthorizationBudget) async -> PortalSnapshotAcquisitionResult
  package typealias BeforeTaskInstall = @Sendable () async -> Void

  package let source = ProductM2AuthorizationSource.nativePortal
  package let availabilityFailure: ProductM2AuthorizationFailure? = nil
  private let acquirePortal: AcquirePortal
  private let beforeTaskInstall: BeforeTaskInstall

  package init(
    acquirePortal: @escaping AcquirePortal
  ) {
    self.acquirePortal = acquirePortal
    beforeTaskInstall = {}
  }

  package init(
    acquirePortal: @escaping AcquirePortal,
    beforeTaskInstall: @escaping BeforeTaskInstall
  ) {
    self.acquirePortal = acquirePortal
    self.beforeTaskInstall = beforeTaskInstall
  }

  package func beginAcquire(
    budget: ProductM2AuthorizationBudget
  ) -> ProductM2AuthorizationAttempt {
    let cancellation = ProductM2PortalAcquisitionCancellation()
    let acquirePortal = self.acquirePortal
    let beforeTaskInstall = self.beforeTaskInstall
    return ProductM2AuthorizationAttempt(
      source: .nativePortal,
      operation: {
        let startGate = ProductM2PortalAcquisitionStartGate()
        let task = Task {
          guard await startGate.waitForStartDecision() else {
            return Self.cancelledAcquisition()
          }
          return await Self.acquire(acquirePortal: acquirePortal, budget: budget)
        }
        await beforeTaskInstall()
        cancellation.install(task, startGate: startGate)
        return await task.value
      },
      cancel: cancellation.cancel
    )
  }

  private static func cancelledAcquisition() -> ProductM2AuthorizedResourceAcquisition {
    .rejected(
      source: .nativePortal,
      failure: .cancelled,
      cleanup: ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: true,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    )
  }

  private static func acquire(
    acquirePortal: @escaping AcquirePortal,
    budget: ProductM2AuthorizationBudget
  ) async -> ProductM2AuthorizedResourceAcquisition {
    guard budget.work.hasRemaining else {
      return .rejected(
        source: .nativePortal,
        failure: .timedOut,
        cleanup: ProductM2AuthorizationCloseReceipt(
          outcome: .notRequired,
          ownedMaterialErased: true,
          sourceCloseRequested: false,
          serverContactRequested: false
        )
      )
    }
    switch await acquirePortal(budget) {
    case .acquired(let portalLease):
      return .acquired(
        source: .nativePortal,
        lease: Self.authorizationLease(portalLease),
        serverContactRequested: true
      )
    case .rejected(let report):
      let operations = report.operations
      return .rejected(
        source: .nativePortal,
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
      close: { deadline in
        guard deadline.remainingMilliseconds(cappedAt: 20_000) == 20_000 else {
          portalLease.snapshot.erase()
          return ProductM2AuthorizationCloseReceipt(
            outcome: .timedOut,
            ownedMaterialErased: portalLease.snapshot.isErased,
            sourceCloseRequested: false,
            serverContactRequested: false
          )
        }
        let logout = await portalLease.logoutAndErase()
        let status = logout.status
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
    let mapping = AuthenticatedPortalSnapshotMapper.mapClassified(snapshot)
    if let failure = mapping.failure {
      throw ProductM2AuthorizedResourceSelectionError.prepareRemap(failure)
    }
    let candidates = mapping.candidates.filter { $0.summary.handle == handle }
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
    let mapping = AuthenticatedPortalSnapshotMapper.mapClassified(snapshot)
    if let failure = mapping.failure {
      throw ProductM2AuthorizedResourceSelectionError.catalogMapping(failure)
    }
    return mapping.candidates
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
