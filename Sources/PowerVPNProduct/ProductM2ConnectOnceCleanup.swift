import Foundation
import PowerVPNCore

package struct ProductM2CleanupResult: Sendable {
  let path: ProductM2CleanupPath
  let stop: ProductM2ControlReceipt
  let emergencyStop: ProductM2ControlReceipt
  let authorizationClose: ProductM2AuthorizationCloseReceipt
  let evidence: ProductM2CleanupEvidence
  let verified: Bool
}

package struct ProductM2CleanupRunner: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies

  func run(
    baseline: ProductM2NetworkBaseline,
    networkWindow: NetworkCleanupCaptureWindow,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease?,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    controlLease: ProductM2ControlLease?,
    startReceipt: ProductM2ControlReceipt
  ) async -> ProductM2CleanupResult {
    let control = await closeControl(
      coldGeneration: coldGeneration,
      controlLease: controlLease,
      startReceipt: startReceipt
    )
    let authorizationClose = await closeAuthorization(authorizationLease)
    let verifier = dependencies.verifyCleanup
    let evidence = await Task.detached {
      await verifier(
        baseline,
        networkWindow,
        selectedRoutes,
        startReceipt.requestSent
      )
    }.value
    let authorizationClosed =
      authorizationLease == nil
      || (authorizationClose.outcome == .accepted
        && authorizationClose.ownedMaterialErased)
    let controlClassified = control.path != .cleanupUnproven
    return ProductM2CleanupResult(
      path: control.path,
      stop: control.stop,
      emergencyStop: control.emergencyStop,
      authorizationClose: authorizationClose,
      evidence: evidence,
      verified: authorizationClosed && controlClassified && evidence.allDimensionsRestored
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

  private func closeAuthorization(
    _ lease: ProductM2AuthorizedResourceLease?
  ) async -> ProductM2AuthorizationCloseReceipt {
    guard let lease else {
      return ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: false,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    }
    return await Task.detached { await lease.closeAndErase() }.value
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

  mutating func apply(_ cleanup: ProductM2CleanupResult) {
    cleanupPath = cleanup.path
    stopOutcome = cleanup.stop.outcome
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
      startOutcome: startOutcome,
      vendorStatusEvidence: vendorStatusEvidence,
      activeNetworkEvidence: activeNetworkEvidence,
      sshProof: sshProof,
      sshProofEvidence: sshProofEvidence,
      cleanupPath: cleanupPath,
      stopOutcome: stopOutcome,
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
