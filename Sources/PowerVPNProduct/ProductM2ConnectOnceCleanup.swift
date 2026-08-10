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
    provisionalStopCapability: ProductM2ProvisionalStopCapability?,
    startReceipt: ProductM2ControlReceipt,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2CleanupResult {
    let completedControl = await closeControl(
      coldGeneration: coldGeneration,
      controlLease: controlLease,
      provisionalStopCapability: provisionalStopCapability,
      startReceipt: startReceipt,
      deadline: budget.controlCleanup
    )
    let controlCompletedWithinDeadline =
      completedControl.path == .notRequired || budget.controlCleanup.hasRemaining
    let control =
      controlCompletedWithinDeadline
      ? completedControl : completedControl.invalidatedByDeadline
    let authorizationClose = await closeAuthorization(
      authorizationLease,
      deadline: budget.authorizationCleanup
    )
    let authorizationCompletedWithinDeadline =
      authorizationLease == nil || budget.authorizationCleanup.hasRemaining
    let verifier = dependencies.verifyCleanup
    let evidence = await Task.detached {
      await verifier(
        baseline,
        networkWindow,
        selectedRoutes,
        startReceipt.requestSent,
        budget.verification
      )
    }.value
    let verificationCompletedWithinDeadline = budget.verification.hasRemaining
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
    controlLease: ProductM2ControlLease?,
    provisionalStopCapability: ProductM2ProvisionalStopCapability?,
    startReceipt: ProductM2ControlReceipt,
    deadline: ProductM2StageDeadline
  ) async -> ControlCleanup {
    if let controlLease {
      guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
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
        deadline: deadline
      )
    }

    if let provisionalStopCapability {
      guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
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
        deadline: deadline
      )
    }

    guard startReceipt.requestSent else { return .notRequired }
    return await classifyPostStartGeneration(
      coldGeneration: coldGeneration,
      stop: .unsent(.notAttempted),
      deadline: deadline
    )
  }

  private func classifyPostStartGeneration(
    coldGeneration: VendorHelperGenerationSnapshot,
    stop: ProductM2ControlReceipt,
    deadline: ProductM2StageDeadline
  ) async -> ControlCleanup {
    guard deadline.hasRemaining else {
      return .deadlineExceeded(stop: stop)
    }
    let observe = dependencies.observeGeneration
    let shieldedObservation: @Sendable () async -> VendorHelperGenerationSnapshot = {
      await Task.detached { await observe(deadline) }.value
    }
    let post = await shieldedObservation()
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

    let control = dependencies.control
    guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
      return .deadlineExceeded(stop: stop)
    }
    let emergency = await Task.detached {
      await control.emergencyStop(
        timeoutMilliseconds: timeout,
        expectedRunningPredicate: {
          ProductM2GenerationFence.singleRunningGeneration(
            coldGeneration,
            await shieldedObservation()
          )
        },
        peerGenerationValidator: {
          ProductM2GenerationFence.validatesReply(
            before: coldGeneration,
            current: await shieldedObservation()
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
