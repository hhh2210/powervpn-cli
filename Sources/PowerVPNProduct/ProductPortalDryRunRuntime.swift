import Foundation
import PowerVPNCore
import PowerVPNPortal

public struct ProductPortalDryRunRuntime: Sendable {
  package typealias AcquirePortal = @Sendable () async -> PortalSnapshotAcquisitionResult

  private let acquirePortal: AcquirePortal

  public init() {
    acquirePortal = { await PortalLoginRuntime.acquireCurrentMachine() }
  }

  package init(acquirePortal: @escaping AcquirePortal) {
    self.acquirePortal = acquirePortal
  }

  public func run(_ request: ProductPortalDryRunRequest) async -> ProductPortalDryRunReport {
    guard Self.validDisplayName(request.resourceDisplayName) else {
      return Self.reportBeforeAcquisition(outcome: .invalidRequest)
    }
    guard !Task.isCancelled else {
      return Self.reportBeforeAcquisition(outcome: .cancelled)
    }

    switch await acquirePortal() {
    case .rejected(let report):
      return Self.rejectedAcquisition(report)
    case .acquired(let lease):
      return await inspectAndClose(lease: lease, request: request)
    }
  }

  private func inspectAndClose(
    lease: AuthenticatedPortalLease,
    request: ProductPortalDryRunRequest
  ) async -> ProductPortalDryRunReport {
    var inspection = InspectionResult()
    if Task.isCancelled {
      inspection.outcome = .cancelled
    } else {
      inspect(lease.snapshot, request: request, result: &inspection)
    }

    let logout = await lease.logoutAndErase()
    let logoutOutcome = ProductPortalDryRunLogoutOutcome(logout.status)
    let erased = lease.snapshot.isErased
    let outcome: ProductPortalDryRunOutcome
    if Task.isCancelled || inspection.outcome == .cancelled || logoutOutcome == .cancelled {
      outcome = .cancelled
    } else if inspection.outcome == .accepted, !erased {
      outcome = .ownedMaterialEraseRejected
    } else if inspection.outcome == .accepted, logoutOutcome != .accepted {
      outcome = .logoutRejected
    } else {
      outcome = inspection.outcome
    }

    return ProductPortalDryRunReport(
      outcome: outcome,
      portalAcquisitionStatus: .accepted,
      operations: ProductPortalDryRunOperations(
        portalAcquisitionRequested: true,
        loginRequested: true,
        loginAccepted: true,
        resourceListRequested: true,
        resourceListAccepted: true,
        sessionCheckRequested: false,
        sessionCheckAccepted: false,
        startSnapshotValidationRequested: inspection.validationRequested,
        startSnapshotConstructed: inspection.startSnapshotComplete,
        targetRouteValidationRequested: inspection.targetValidationRequested,
        logoutAttempted: true,
        logoutAccepted: logoutOutcome == .accepted
      ),
      candidateCount: inspection.candidateCount,
      matchingCandidateCount: inspection.matchingCandidateCount,
      selectedCandidateCount: inspection.selectedCandidateCount,
      startSnapshotComplete: inspection.startSnapshotComplete,
      targetRouteCovered: inspection.targetRouteCovered,
      logoutOutcome: logoutOutcome,
      ownedMaterialErased: erased,
      resourceCatalogFailure: inspection.resourceCatalogFailure,
      logoutFailureClass: ProductPortalLogoutFailureClass(logout.failureClass)
    )
  }

  private func inspect(
    _ snapshot: AuthenticatedPortalSnapshot,
    request: ProductPortalDryRunRequest,
    result: inout InspectionResult
  ) {
    let (candidates, catalogFailure) = AuthenticatedPortalSnapshotMapper.mapClassified(
      snapshot
    )
    guard catalogFailure == nil else {
      result.outcome = .resourceCatalogRejected
      result.resourceCatalogFailure = catalogFailure
      return
    }
    result.candidateCount = candidates.count
    let matches = candidates.filter { $0.summary.displayName == request.resourceDisplayName }
    result.matchingCandidateCount = matches.count
    guard !matches.isEmpty else {
      result.outcome = .resourceNotFound
      return
    }
    guard matches.count == 1 else {
      result.outcome = .resourceAmbiguous
      return
    }
    result.selectedCandidateCount = 1
    result.validationRequested = true

    do {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        snapshot,
        handle: matches[0].summary.handle
      ) { startSnapshot in
        result.startSnapshotComplete = true
        result.targetValidationRequested = true
        _ = try startSnapshot.makeSelectedRouteMatcher(
          requiredTargetIPv4: request.sshTarget.requiredTargetIPv4
        )
        result.targetRouteCovered = true
      }
      result.outcome = .accepted
    } catch AuthenticatedPortalValidatedSnapshotError.incompleteSnapshot {
      result.outcome = .startSnapshotIncomplete
    } catch VendorCharonSelectedRouteMatcherError.requiredTargetNotCovered {
      result.outcome = .targetRouteNotCovered
    } catch {
      result.outcome = .startSnapshotRejected
    }
  }

  private static func validDisplayName(_ value: String) -> Bool {
    (1...256).contains(value.utf8.count)
      && !value.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0)
      }
  }
}

private struct InspectionResult {
  var outcome = ProductPortalDryRunOutcome.startSnapshotRejected
  var resourceCatalogFailure: ProductResourceCatalogFailure?
  var candidateCount = 0
  var matchingCandidateCount = 0
  var selectedCandidateCount = 0
  var validationRequested = false
  var startSnapshotComplete = false
  var targetValidationRequested = false
  var targetRouteCovered = false
}

extension ProductPortalDryRunLogoutOutcome {
  fileprivate init(_ status: PortalLeaseLogoutStatus) {
    switch status {
    case .accepted: self = .accepted
    case .rejected: self = .rejected
    case .timedOut: self = .timedOut
    case .cancelled: self = .cancelled
    case .alreadyClosed: self = .alreadyClosed
    }
  }
}

extension ProductPortalLogoutFailureClass {
  fileprivate init?(_ failureClass: PortalLeaseLogoutFailureClass?) {
    guard let failureClass else { return nil }
    switch failureClass {
    case .requestConstructionFailed: self = .requestConstructionFailed
    case .transportFailed: self = .transportFailed
    case .completedRemoteExchange: self = .completedRemoteExchange
    case .acceptedRemoteExchange: self = .acceptedRemoteExchange
    }
  }
}

extension ProductPortalDryRunRuntime {
  private static func reportBeforeAcquisition(
    outcome: ProductPortalDryRunOutcome
  ) -> ProductPortalDryRunReport {
    ProductPortalDryRunReport(
      outcome: outcome,
      portalAcquisitionStatus: .notRequested,
      operations: ProductPortalDryRunOperations(
        portalAcquisitionRequested: false,
        loginRequested: false,
        loginAccepted: false,
        resourceListRequested: false,
        resourceListAccepted: false,
        sessionCheckRequested: false,
        sessionCheckAccepted: false,
        startSnapshotValidationRequested: false,
        startSnapshotConstructed: false,
        targetRouteValidationRequested: false,
        logoutAttempted: false,
        logoutAccepted: false
      ),
      candidateCount: 0,
      matchingCandidateCount: 0,
      selectedCandidateCount: 0,
      startSnapshotComplete: false,
      targetRouteCovered: false,
      logoutOutcome: .notRequired,
      ownedMaterialErased: true
    )
  }

  private static func rejectedAcquisition(
    _ report: PortalLoginReport
  ) -> ProductPortalDryRunReport {
    let operations = report.operations
    let logoutOutcome: ProductPortalDryRunLogoutOutcome =
      !operations.logoutRequested
      ? .notRequired
      : operations.logoutAccepted
        ? .accepted
        : report.status == .cancelled ? .cancelled : .rejected
    return ProductPortalDryRunReport(
      outcome: report.status == .cancelled ? .cancelled : .portalAcquisitionRejected,
      portalAcquisitionStatus: ProductPortalAcquisitionStatus(report.status),
      portalTransportFailure: report.transportFailure,
      operations: ProductPortalDryRunOperations(
        portalAcquisitionRequested: true,
        loginRequested: operations.loginRequested,
        loginAccepted: operations.loginAccepted,
        resourceListRequested: operations.resourceListRequested,
        resourceListAccepted: operations.resourceListAccepted,
        sessionCheckRequested: operations.sessionCheckRequested,
        sessionCheckAccepted: operations.sessionCheckAccepted,
        startSnapshotValidationRequested: false,
        startSnapshotConstructed: false,
        targetRouteValidationRequested: false,
        logoutAttempted: operations.logoutRequested,
        logoutAccepted: operations.logoutAccepted
      ),
      candidateCount: 0,
      matchingCandidateCount: 0,
      selectedCandidateCount: 0,
      startSnapshotComplete: false,
      targetRouteCovered: false,
      logoutOutcome: logoutOutcome,
      ownedMaterialErased: report.ownedMaterial.credentialsErased
        && report.ownedMaterial.requestBodiesErased
        && report.ownedMaterial.responseBodiesErased
        && report.ownedMaterial.sessionMaterialErased
    )
  }
}

extension ProductPortalAcquisitionStatus {
  fileprivate init(_ status: PortalLoginStatus) {
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
