import Foundation
import PowerVPNCore

package struct ProductM2CleanupResult: Sendable {
  let path: ProductM2CleanupPath
  let stop: ProductM2ControlReceipt
  let emergencyStop: ProductM2ControlReceipt
  let portalLogout: ProductM2PortalLogoutOutcome
  let evidence: ProductM2CleanupEvidence
  let verified: Bool
}

package struct ProductM2CleanupRunner: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies

  func run(
    baseline: ProductM2NetworkBaseline,
    coldGeneration: VendorHelperGenerationSnapshot,
    portalLease: (any ProductM2PortalLeasing)?,
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
    let evidence = await Task.detached { await verifier(baseline) }.value
    let portalClosed = portalLease == nil || logout == .accepted
    let controlClassified = control.path != .cleanupUnproven
    return ProductM2CleanupResult(
      path: control.path,
      stop: control.stop,
      emergencyStop: control.emergencyStop,
      portalLogout: logout,
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
    let post = dependencies.observeGeneration()
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
            observe()
          )
        },
        peerGenerationValidator: {
          ProductM2GenerationFence.validatesReply(
            before: coldGeneration,
            current: observe()
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
  ) async -> ProductM2PortalLogoutOutcome {
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
  var outcome: ProductM2ConnectOutcome = .portalAcquisitionRejected
  var finalState: ProductM2ConnectionState = .signedOut
  var lastGoodState: ProductM2ConnectionState = .signedOut
  var firstBadEvent: ProductM2BadEvent?
  var portalAcquisition: ProductM2PortalAcquisitionOutcome = .notRequested
  var startOutcome: ProductM2ControlOutcome = .notAttempted
  var sshProof: ProductM2SSHProofOutcome = .notAttempted
  var cleanupPath: ProductM2CleanupPath = .notRequired
  var stopOutcome: ProductM2ControlOutcome = .notAttempted
  var emergencyStopOutcome: ProductM2ControlOutcome = .notAttempted
  var portalLogout: ProductM2PortalLogoutOutcome = .notRequired
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
    portalLogout = cleanup.portalLogout
    cleanupEvidence = cleanup.evidence
    cleanupVerified = cleanup.verified
    helperMutationRequested =
      helperMutationRequested
      || cleanup.stop.requestSent || cleanup.emergencyStop.requestSent

    guard cleanup.verified else {
      if firstBadEvent == nil {
        firstBadEvent =
          cleanup.portalLogout == .accepted
            || cleanup.portalLogout == .notRequired
          ? .cleanupVerificationRejected : .portalLogoutRejected
      }
      outcome = .cleanupUnproven
      finalState = .failed
      return
    }
    if outcome == .connectedAndCleanedUp {
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
      portalAcquisition: portalAcquisition,
      startOutcome: startOutcome,
      sshProof: sshProof,
      cleanupPath: cleanupPath,
      stopOutcome: stopOutcome,
      emergencyStopOutcome: emergencyStopOutcome,
      portalLogout: portalLogout,
      cleanupEvidence: cleanupEvidence,
      cleanupVerified: cleanupVerified,
      serverContactRequested: serverContactRequested,
      helperMutationRequested: helperMutationRequested
    )
  }
}
