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

struct ProductM2ControlCleanupAuthority: Sendable {
  let lease: ProductM2ControlLease?
  let provisionalStop: ProductM2ProvisionalStopCapability?
  let emergencyStop: ProductM2EmergencyStopCapability?
  let startReceipt: ProductM2ControlReceipt
}

package struct ProductM2CleanupRunner: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies

  func run(
    baseline: ProductM2NetworkBaseline,
    networkWindow: NetworkCleanupCaptureWindow,
    coldGeneration: VendorHelperGenerationSnapshot,
    authorizationLease: ProductM2AuthorizedResourceLease?,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    controlAuthority: ProductM2ControlCleanupAuthority,
    deadlines: ProductM2CleanupDeadlines
  ) async -> ProductM2CleanupResult {
    let completedControl = await closeControl(
      coldGeneration: coldGeneration,
      authority: controlAuthority,
      deadline: deadlines.controlCleanup,
      reportDeadline: deadlines.report
    )
    let controlCompletedWithinDeadline =
      completedControl.path == .notRequired || deadlines.controlCleanup.hasRemaining
    let control =
      controlCompletedWithinDeadline
      ? completedControl : completedControl.invalidatedByDeadline
    let authorizationClose = await closeAuthorization(
      authorizationLease,
      deadline: deadlines.authorizationCleanup
    )
    let authorizationCompletedWithinDeadline =
      authorizationLease == nil || deadlines.authorizationCleanup.hasRemaining
    let verifier = dependencies.verifyCleanup
    let evidence = await Task.detached {
      await verifier(
        baseline,
        networkWindow,
        selectedRoutes,
        controlAuthority.startReceipt.requestSent,
        deadlines.verification
      )
    }.value
    let verificationCompletedWithinDeadline = deadlines.verification.hasRemaining
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
      verified: controlCompletedWithinDeadline
        && authorizationCompletedWithinDeadline
        && verificationCompletedWithinDeadline
        && authorizationClosed
        && controlClassified
        && evidence.allDimensionsRestored
    )
  }

  private func closeControl(
    coldGeneration: VendorHelperGenerationSnapshot,
    authority: ProductM2ControlCleanupAuthority,
    deadline: ProductM2StageDeadline,
    reportDeadline: ProductM2StageDeadline
  ) async -> ControlCleanup {
    if let controlLease = authority.lease {
      guard
        let operationDeadline = availableControlDeadline(
          deadline,
          reportDeadline: reportDeadline
        ),
        let timeout = operationDeadline.remainingMilliseconds(cappedAt: 2_000)
      else {
        return .deadlineExceeded
      }
      let stop = await Task.detached {
        await controlLease.stop(timeoutMilliseconds: timeout)
      }.value
      guard !stop.requestSent else {
        return ControlCleanup(
          path: .sameLeaseStop,
          stop: stop,
          emergencyStop: .unsent(.notAttempted)
        )
      }
      return await classifyPostStartGeneration(
        coldGeneration: coldGeneration,
        stop: stop,
        emergencyStopCapability: authority.emergencyStop,
        deadline: deadline,
        reportDeadline: reportDeadline
      )
    }

    if let provisionalStopCapability = authority.provisionalStop {
      guard
        let operationDeadline = availableControlDeadline(
          deadline,
          reportDeadline: reportDeadline
        ),
        let timeout = operationDeadline.remainingMilliseconds(cappedAt: 2_000)
      else {
        return .deadlineExceeded
      }
      let stop = await Task.detached {
        await provisionalStopCapability.stop(timeoutMilliseconds: timeout)
      }.value
      guard !stop.requestSent else {
        return ControlCleanup(
          path: .sameSessionProvisionalStop,
          stop: stop,
          emergencyStop: .unsent(.notAttempted)
        )
      }
      return await classifyPostStartGeneration(
        coldGeneration: coldGeneration,
        stop: stop,
        emergencyStopCapability: authority.emergencyStop,
        deadline: deadline,
        reportDeadline: reportDeadline
      )
    }

    guard authority.startReceipt.requestSent else { return .notRequired }
    return await classifyPostStartGeneration(
      coldGeneration: coldGeneration,
      stop: .unsent(.notAttempted),
      emergencyStopCapability: authority.emergencyStop,
      deadline: deadline,
      reportDeadline: reportDeadline
    )
  }

  private func classifyPostStartGeneration(
    coldGeneration: VendorHelperGenerationSnapshot,
    stop: ProductM2ControlReceipt,
    emergencyStopCapability: ProductM2EmergencyStopCapability?,
    deadline: ProductM2StageDeadline,
    reportDeadline: ProductM2StageDeadline
  ) async -> ControlCleanup {
    guard
      let observationDeadline = availableControlDeadline(
        deadline,
        reportDeadline: reportDeadline
      )
    else {
      return .deadlineExceeded(stop: stop)
    }
    let observe = dependencies.observeGeneration
    let shieldedObservation:
      @Sendable (ProductM2StageDeadline) async -> VendorHelperGenerationSnapshot =
        { observationDeadline in
          await Task.detached { await observe(observationDeadline) }.value
        }
    let post = await shieldedObservation(observationDeadline)
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
    guard let emergencyStopCapability else {
      return ControlCleanup(
        path: .cleanupUnproven,
        stop: stop,
        emergencyStop: .unsent(.notAttempted)
      )
    }
    guard
      let emergencyDeadline = availableControlDeadline(
        deadline,
        reportDeadline: reportDeadline
      ),
      let timeout = emergencyDeadline.remainingMilliseconds(cappedAt: 2_000)
    else {
      return .deadlineExceeded(stop: stop)
    }
    let emergency = await Task.detached {
      await emergencyStopCapability.stop(
        timeoutMilliseconds: timeout,
        expectedRunningPredicate: {
          ProductM2GenerationFence.singleRunningGeneration(
            coldGeneration,
            await shieldedObservation(emergencyDeadline)
          )
        },
        peerGenerationValidator: {
          ProductM2GenerationFence.validatesReply(
            before: coldGeneration,
            current: await shieldedObservation(emergencyDeadline)
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

  private func availableControlDeadline(
    _ deadline: ProductM2StageDeadline,
    reportDeadline: ProductM2StageDeadline
  ) -> ProductM2StageDeadline? {
    if deadline.hasRemaining { return deadline }
    return reportDeadline.hasRemaining ? reportDeadline : nil
  }

  private func closeAuthorization(
    _ lease: ProductM2AuthorizedResourceLease?,
    deadline: ProductM2StageDeadline
  ) async -> ProductM2AuthorizationCloseReceipt {
    guard let lease else {
      return ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: false,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    }
    return await Task.detached { await lease.closeAndErase(deadline: deadline) }.value
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

  static let deadlineExceeded = Self.deadlineExceeded(
    stop: .unsent(.timeout)
  )

  static func deadlineExceeded(
    stop: ProductM2ControlReceipt
  ) -> Self {
    Self(
      path: .cleanupUnproven,
      stop: stop,
      emergencyStop: .unsent(.timeout)
    )
  }

  var invalidatedByDeadline: Self {
    Self(
      path: .cleanupUnproven,
      stop: stop,
      emergencyStop: emergencyStop
    )
  }
}
