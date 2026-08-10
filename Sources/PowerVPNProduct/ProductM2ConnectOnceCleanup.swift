import Foundation
import PowerVPNCore

package struct ProductM2CleanupResult: Sendable {
  let path: ProductM2CleanupPath
  let stop: ProductM2ControlReceipt
  let emergencyStop: ProductM2ControlReceipt
  let authorizationClose: ProductM2AuthorizationCloseOutcome
  let evidence: ProductM2CleanupEvidence
  let verified: Bool
}

package struct ProductM2CleanupRunner: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies

  func run(
    baseline: ProductM2NetworkBaseline,
    networkWindow: NetworkCleanupCaptureWindow,
    coldGeneration: VendorHelperGenerationSnapshot,
    portalLease: (any ProductM2PortalLeasing)?,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    controlLease: ProductM2ControlLease?,
    startReceipt: ProductM2ControlReceipt
  ) async -> ProductM2CleanupResult {
    let control = await closeControl(
      coldGeneration: coldGeneration,
      controlLease: controlLease,
      startReceipt: startReceipt
    )
    let logout = await closePortal(portalLease)
    let verifier = dependencies.verifyCleanup
    let evidence = await Task.detached {
      await verifier(
        baseline,
        networkWindow,
        selectedRoutes,
        startReceipt.requestSent
      )
    }.value
    let portalClosed = portalLease == nil || logout == .accepted
    let controlClassified = control.path != .cleanupUnproven
    return ProductM2CleanupResult(
      path: control.path,
      stop: control.stop,
      emergencyStop: control.emergencyStop,
      authorizationClose: logout,
      evidence: evidence,
      verified: portalClosed && controlClassified && evidence.allDimensionsRestored
    )
  }

  private func closeControl(
    coldGeneration: VendorHelperGenerationSnapshot,
    controlLease: ProductM2ControlLease?,
    startReceipt: ProductM2ControlReceipt
  ) async -> ControlCleanup {
    if let controlLease {
      let stop = await Task.detached { await controlLease.stop() }.value
      guard !stop.requestSent else {
        return ControlCleanup(
          path: .sameLeaseStop,
          stop: stop,
          emergencyStop: .unsent(.notAttempted)
        )
      }
      return await classifyPostStartGeneration(
        coldGeneration: coldGeneration,
        stop: stop
      )
    }

    guard startReceipt.requestSent else { return .notRequired }
    return await classifyPostStartGeneration(
      coldGeneration: coldGeneration,
      stop: .unsent(.notAttempted)
    )
  }

  private func classifyPostStartGeneration(
    coldGeneration: VendorHelperGenerationSnapshot,
    stop: ProductM2ControlReceipt
  ) async -> ControlCleanup {
    let post = await dependencies.observeGeneration()
    if ProductM2GenerationFence.singleExitedGeneration(coldGeneration, post) {
      return ControlCleanup(
        path: .naturalHelperExit,
        stop: stop,
        emergencyStop: .unsent(.notAttempted)
      )
    }
    guard ProductM2GenerationFence.singleRunningGeneration(coldGeneration, post) else {
      return ControlCleanup(
        path: .cleanupUnproven,
        stop: stop,
        emergencyStop: .unsent(.notAttempted)
      )
    }

    let observe = dependencies.observeGeneration
    let control = dependencies.control
    let emergency = await Task.detached {
      await control.emergencyStop(
        expectedRunningPredicate: {
          ProductM2GenerationFence.singleRunningGeneration(
            coldGeneration,
            await observe()
          )
        },
        peerGenerationValidator: {
          ProductM2GenerationFence.validatesReply(
            before: coldGeneration,
            current: await observe()
          )
        }
      )
    }.value
    return ControlCleanup(
      path: .authenticatedEmergencyStop,
      stop: stop,
      emergencyStop: emergency
    )
  }

  private func closePortal(
    _ lease: (any ProductM2PortalLeasing)?
  ) async -> ProductM2AuthorizationCloseOutcome {
    guard let lease else { return .notRequired }
    let status = await Task.detached { await lease.logoutAndErase() }.value
    switch status {
    case .accepted: return .accepted
    case .rejected: return .rejected
    case .timedOut: return .timedOut
    case .cancelled: return .cancelled
    case .alreadyClosed: return .alreadyClosed
    }
  }
}

private struct ControlCleanup {
  let path: ProductM2CleanupPath
  let stop: ProductM2ControlReceipt
  let emergencyStop: ProductM2ControlReceipt

  static let notRequired = Self(
    path: .notRequired,
    stop: .unsent(.notAttempted),
    emergencyStop: .unsent(.notAttempted)
  )
}

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
  var startOutcome: ProductM2ControlOutcome = .notAttempted
  var vendorStatusEvidence = ProductM2VendorStatusEvidence.notAttempted
  var activeNetworkEvidence = ProductM2ActiveNetworkEvidence.unavailable
  var sshProof: ProductM2SSHProofOutcome = .notAttempted
  var sshProofEvidence: ProductM2FreshSSHProofEvidence?
  var cleanupPath: ProductM2CleanupPath = .notRequired
  var stopOutcome: ProductM2ControlOutcome = .notAttempted
  var emergencyStopOutcome: ProductM2ControlOutcome = .notAttempted
  var authorizationClose: ProductM2AuthorizationCloseOutcome = .notRequired
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

  mutating func apply(_ cleanup: ProductM2CleanupResult) {
    cleanupPath = cleanup.path
    stopOutcome = cleanup.stop.outcome
    emergencyStopOutcome = cleanup.emergencyStop.outcome
    authorizationClose = cleanup.authorizationClose
    cleanupEvidence = cleanup.evidence
    cleanupVerified = cleanup.verified
    helperMutationRequested =
      helperMutationRequested
      || cleanup.stop.requestSent || cleanup.emergencyStop.requestSent

    guard cleanup.verified else {
      if firstBadEvent == nil {
        firstBadEvent =
          cleanup.authorizationClose == .accepted
            || cleanup.authorizationClose == .notRequired
          ? .cleanupVerificationRejected : .authorizationCloseRejected
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
      startOutcome: startOutcome,
      vendorStatusEvidence: vendorStatusEvidence,
      activeNetworkEvidence: activeNetworkEvidence,
      sshProof: sshProof,
      sshProofEvidence: sshProofEvidence,
      cleanupPath: cleanupPath,
      stopOutcome: stopOutcome,
      emergencyStopOutcome: emergencyStopOutcome,
      authorizationClose: authorizationClose,
      cleanupEvidence: cleanupEvidence,
      cleanupVerified: cleanupVerified,
      serverContactRequested: serverContactRequested,
      helperMutationRequested: helperMutationRequested
    )
  }
}
