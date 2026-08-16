import PowerVPNCore

package struct ProductM2Execution {
  let request: ProductM2ConnectRequest
  let networkWindow: NetworkCleanupCaptureWindow
  var outcome: ProductM2ConnectOutcome = .authorizationAcquisitionRejected
  var finalState: ProductM2ConnectionState = .signedOut
  var lastGoodState: ProductM2ConnectionState = .signedOut
  var firstBadEvent: ProductM2BadEvent?
  var authorizationSource: ProductM2AuthorizationSource
  var authorizationAcquisition: ProductM2AuthorizationAcquisitionOutcome = .notRequested
  var authorizationFailure: ProductM2AuthorizationFailure?
  var resourceCatalogFailure: ProductResourceCatalogFailure?
  var selectionFailureClass: ProductM2SelectionFailureClass?
  var startOutcome: ProductM2ControlOutcome = .notAttempted
  var startEventSignatures: [String]?
  var startReplySignatures: [String]?
  var unexpectedEventSignature: [String]?
  var vendorStatusEvidence = ProductM2VendorStatusEvidence.notAttempted
  var activeNetworkEvidence = ProductM2ActiveNetworkEvidence.unavailable
  var activeCaptureState: ProductM2ActiveCaptureState? = nil
  var activeCaptureChangeAxes: [ProductM2ActiveCaptureChangeAxis]? = nil
  var activeCaptureIncompleteReason: ProductM2ActiveCaptureIncompleteReason? = nil
  var sshProof: ProductM2SSHProofOutcome = .notAttempted
  var sshProofEvidence: ProductM2FreshSSHProofEvidence?
  var cleanupPath: ProductM2CleanupPath = .notRequired
  var stopOutcome: ProductM2ControlOutcome = .notAttempted
  var stopInvalidityClass: ProductM2StopInvalidityClass? = nil
  var emergencyStopOutcome: ProductM2ControlOutcome = .notAttempted
  var authorizationClose: ProductM2AuthorizationCloseOutcome = .notRequired
  var authorizationOwnedMaterialErased = true
  var cleanupEvidence = ProductM2CleanupEvidence.unavailable
  var cleanupVerified = false
  var serverContactRequested = false
  var helperMutationRequested = false

  mutating func fail(
    _ outcome: ProductM2ConnectOutcome,
    event: ProductM2BadEvent,
    state: ProductM2ConnectionState
  ) {
    self.outcome = outcome
    firstBadEvent = firstBadEvent ?? event
    finalState = state
  }

  mutating func applySelectionFailure(_ error: Error) {
    let outcome: ProductM2ConnectOutcome
    let event: ProductM2BadEvent
    switch error {
    case ProductM2AuthorizedResourceSelectionError.resourceNotFound:
      (outcome, event) = (.resourceNotFound, .resourceNotFound)
    case ProductM2AuthorizedResourceSelectionError.resourceAmbiguous:
      (outcome, event) = (.resourceAmbiguous, .resourceAmbiguous)
    case ProductM2AuthorizedResourceSelectionError.selectedRouteCoverageRejected:
      (outcome, event) = (.selectedRouteCoverageRejected, .selectedRouteCoverageRejected)
    case ProductM2AuthorizedResourceSelectionError.startSnapshotRejected:
      (outcome, event) = (.startSnapshotRejected, .startSnapshotRejected)
    case ProductM2AuthorizedResourceSelectionError.catalogMapping(let failure):
      resourceCatalogFailure = failure
      selectionFailureClass = .catalogMapping
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    case ProductM2AuthorizedResourceSelectionError.catalogEmpty:
      selectionFailureClass = .catalogEmpty
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    case ProductM2AuthorizedResourceSelectionError.catalogInvariantInvalid:
      selectionFailureClass = .catalogInvariantInvalid
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    case ProductM2AuthorizedResourceSelectionError.prepareRemap(let failure):
      resourceCatalogFailure = failure
      selectionFailureClass = .prepareRemap
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    case ProductM2AuthorizedResourceSelectionError.leaseClosed,
      ProductM2AuthorizedResourceSelectionError.selectionAlreadyIssued,
      ProductM2AuthorizedResourceSelectionError.startAlreadyIssued,
      ProductM2AuthorizedResourceSelectionError.invalidSelection:
      selectionFailureClass = .selectionReplay
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    case ProductM2AuthorizedResourceSelectionError.preparedSelectionMismatch:
      selectionFailureClass = .preparedSelectionMismatch
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    default:
      selectionFailureClass = .catalogInvariantInvalid
      (outcome, event) = (.resourceCatalogRejected, .resourceCatalogRejected)
    }
    fail(outcome, event: event, state: .blocked)
  }

  mutating func apply(_ cleanup: ProductM2CleanupResult) {
    cleanupPath = cleanup.path
    stopOutcome = cleanup.stop.outcome
    stopInvalidityClass = cleanup.stopInvalidityClass
    emergencyStopOutcome = cleanup.emergencyStop.outcome
    if cleanup.authorizationClose.outcome != .notRequired {
      authorizationClose = cleanup.authorizationClose.outcome
      authorizationOwnedMaterialErased = cleanup.authorizationClose.ownedMaterialErased
    }
    serverContactRequested =
      serverContactRequested || cleanup.authorizationClose.serverContactRequested
    cleanupEvidence = cleanup.evidence
    let authorizationClosed =
      authorizationClose == .accepted || authorizationClose == .notRequired
    cleanupVerified =
      cleanup.verified && authorizationOwnedMaterialErased && authorizationClosed
    helperMutationRequested =
      helperMutationRequested
      || cleanup.stop.requestSent || cleanup.emergencyStop.requestSent

    guard cleanupVerified else {
      if firstBadEvent == nil {
        firstBadEvent =
          authorizationOwnedMaterialErased
          ? (cleanup.authorizationClose.outcome == .accepted
            || cleanup.authorizationClose.outcome == .notRequired
            ? .cleanupVerificationRejected : .authorizationCloseRejected)
          : .authorizationCloseRejected
      }
      outcome = .cleanupUnproven
      finalState = .failed
      return
    }
    if outcome == .connectedAndCleanedUp {
      guard cleanup.path == .sameLeaseStop,
        cleanup.stop.requestSent,
        cleanup.stop.statusEventCount > 0,
        cleanup.stop.statusAtSubmission == .connected
      else {
        let latest = cleanup.stop.statusAtSubmission
        vendorStatusEvidence = ProductM2VendorStatusEvidence(
          outcome: latest == .disconnected ? .disconnected : .leaseClosed,
          statusEventCount: cleanup.stop.statusEventCount,
          latestClassification: latest,
          terminalControlOutcome: latest == nil ? cleanup.stop.outcome : nil
        )
        firstBadEvent = firstBadEvent ?? .vendorStatusUnproven
        outcome = .vendorStatusUnproven
        finalState = .disconnected
        return
      }
      vendorStatusEvidence = ProductM2VendorStatusEvidence(
        outcome: .connected,
        statusEventCount: cleanup.stop.statusEventCount,
        latestClassification: .connected,
        terminalControlOutcome: nil
      )
      lastGoodState = .connected
      finalState = .disconnected
    } else if helperMutationRequested {
      finalState = .disconnected
    }
  }

  func report() -> ProductM2ConnectReport {
    ProductM2ConnectReport(
      outcome: outcome,
      finalState: finalState,
      lastGoodState: lastGoodState,
      firstBadEvent: firstBadEvent,
      resourceDisplayName: request.resourceDisplayName,
      sshTarget: request.sshTarget,
      authorizationSource: authorizationSource,
      authorizationAcquisition: authorizationAcquisition,
      authorizationFailure: authorizationFailure,
      resourceCatalogFailure: resourceCatalogFailure,
      selectionFailureClass: selectionFailureClass,
      startOutcome: startOutcome,
      startEventSignatures: startEventSignatures,
      startReplySignatures: startReplySignatures,
      unexpectedEventSignature: unexpectedEventSignature,
      vendorStatusEvidence: vendorStatusEvidence,
      activeNetworkEvidence: activeNetworkEvidence,
      activeCaptureState: activeCaptureState,
      activeCaptureChangeAxes: activeCaptureChangeAxes,
      activeCaptureIncompleteReason: activeCaptureIncompleteReason,
      sshProof: sshProof,
      sshProofEvidence: sshProofEvidence,
      cleanupPath: cleanupPath,
      stopOutcome: stopOutcome,
      stopInvalidityClass: stopInvalidityClass,
      emergencyStopOutcome: emergencyStopOutcome,
      authorizationClose: authorizationClose,
      authorizationOwnedMaterialErased: authorizationOwnedMaterialErased,
      cleanupEvidence: cleanupEvidence,
      cleanupVerified: cleanupVerified,
      serverContactRequested: serverContactRequested,
      helperMutationRequested: helperMutationRequested
    )
  }
}
