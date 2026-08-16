import PowerVPNCore

package final class ProductPersistentTunnelLease: @unchecked Sendable {
  private let session: ProductPersistentTunnelSession

  init(session: ProductPersistentTunnelSession) {
    self.session = session
  }

  package func permitsIPv4(_ address: UInt32) async -> Bool {
    await session.permitsIPv4(address)
  }

  package func shutdown(
    budget: ProductM2CleanupBudget
  ) async -> ProductPersistentTunnelShutdownReport {
    await session.shutdown(budget: budget)
  }

  // Intentionally no deinit cleanup. Callers must await the truthful shutdown report.
}

actor ProductPersistentTunnelSession {
  private enum Storage {
    case idle
    case starting
    case active(ProductPersistentTunnelSessionAssets)
    case stopping(Task<ProductPersistentTunnelShutdownReport, Never>)
    case stopped(ProductPersistentTunnelShutdownReport)
  }

  private let coordinator: ProductPersistentTunnelCoordinator
  private var storage = Storage.idle

  init(coordinator: ProductPersistentTunnelCoordinator) {
    self.coordinator = coordinator
  }

  func open(
    _ request: ProductM2ConnectRequest,
    startupBudget: ProductM2AbsoluteBudget
  ) async -> ProductPersistentTunnelOpenResult {
    guard case .idle = storage else {
      return .failed(rejectedPreOpenReport())
    }
    storage = .starting
    let result = await coordinator.openSession(request, startupBudget: startupBudget)
    switch result {
    case .active(let assets):
      storage = .active(assets)
      let report = ProductPersistentTunnelOpenReport(
        outcome: .opened,
        failure: nil,
        state: .active,
        helperMutationRequested: true,
        serverContactRequested: true,
        authorizationClose: assets.execution.authorizationClose,
        authorizationOwnedMaterialErased: assets.execution.authorizationOwnedMaterialErased,
        cleanupVerified: false,
        activeCaptureState: assets.execution.activeCaptureState,
        activeCaptureChangeAxes: assets.execution.activeCaptureChangeAxes,
        activeCaptureIncompleteReason: assets.execution.activeCaptureIncompleteReason,
        stopInvalidityClass: assets.execution.stopInvalidityClass,
        networkProofSource: assets.execution.networkProofSource
      )
      return .opened(ProductPersistentTunnelLease(session: self), report)
    case .failed(let failure):
      let report = ProductPersistentTunnelOpenReport(
        outcome: .rejected,
        failure: failure.outcome,
        state: .stopped,
        helperMutationRequested: failure.helperMutationRequested,
        serverContactRequested: failure.serverContactRequested,
        authorizationClose: failure.authorizationClose,
        authorizationOwnedMaterialErased: failure.authorizationOwnedMaterialErased,
        cleanupVerified: failure.cleanupVerified,
        cleanupCaptureState: failure.cleanupCaptureState,
        cleanupCaptureRetryReason: failure.cleanupCaptureRetryReason,
        cleanupCaptureAttemptCount: failure.cleanupCaptureAttemptCount,
        activeCaptureState: failure.activeCaptureState,
        activeCaptureChangeAxes: failure.activeCaptureChangeAxes,
        activeCaptureIncompleteReason: failure.activeCaptureIncompleteReason,
        stopInvalidityClass: failure.stopInvalidityClass,
        networkProofSource: failure.networkProofSource
      )
      storage = .stopped(
        ProductPersistentTunnelShutdownReport(
          state: .stopped,
          cleanupPath: failure.cleanupPath,
          stopOutcome: failure.stopOutcome,
          emergencyStopOutcome: failure.emergencyStopOutcome,
          authorizationClose: failure.authorizationClose,
          authorizationOwnedMaterialErased: failure.authorizationOwnedMaterialErased,
          cleanupVerified: failure.cleanupVerified,
          cleanupCaptureState: failure.cleanupCaptureState,
          cleanupCaptureRetryReason: failure.cleanupCaptureRetryReason,
          cleanupCaptureAttemptCount: failure.cleanupCaptureAttemptCount
        ))
      return .failed(report)
    }
  }
  private func rejectedPreOpenReport() -> ProductPersistentTunnelOpenReport {
    ProductPersistentTunnelOpenReport(
      outcome: .rejected,
      failure: .preflightBlocked,
      state: reportedState,
      helperMutationRequested: false,
      serverContactRequested: false,
      authorizationClose: .notRequired,
      authorizationOwnedMaterialErased: true,
      cleanupVerified: false
    )
  }

  func permitsIPv4(_ address: UInt32) -> Bool {
    guard case .active(let assets) = storage else { return false }
    return assets.selectedRoutes.permitsIPv4(address)
  }

  func shutdown(
    budget: ProductM2CleanupBudget
  ) async -> ProductPersistentTunnelShutdownReport {
    switch storage {
    case .active(let assets):
      let coordinator = coordinator
      let task = Task.detached {
        let cleanup = await coordinator.shutdown(
          assets,
          deadlines: ProductM2CleanupDeadlines(budget)
        )
        return ProductPersistentTunnelShutdownReport(
          state: .stopped,
          cleanupPath: cleanup.verified ? cleanup.path : .cleanupUnproven,
          stopOutcome: cleanup.stop.outcome,
          emergencyStopOutcome: cleanup.emergencyStop.outcome,
          authorizationClose: cleanup.authorizationClose.outcome,
          authorizationOwnedMaterialErased: cleanup.authorizationClose.ownedMaterialErased,
          cleanupVerified: cleanup.verified,
          cleanupCaptureState: cleanup.captureState,
          cleanupCaptureRetryReason: cleanup.captureRetryReason,
          cleanupCaptureAttemptCount: cleanup.captureAttemptCount
        )
      }
      storage = .stopping(task)
      return await completeShutdown(task)
    case .stopping(let task):
      return await completeShutdown(task)
    case .stopped(let report):
      return report
    case .idle, .starting:
      return ProductPersistentTunnelShutdownReport(
        state: reportedState,
        cleanupPath: .notRequired,
        stopOutcome: .notAttempted,
        emergencyStopOutcome: .notAttempted,
        authorizationClose: .notRequired,
        authorizationOwnedMaterialErased: false,
        cleanupVerified: false
      )
    }
  }

  private func completeShutdown(
    _ task: Task<ProductPersistentTunnelShutdownReport, Never>
  ) async -> ProductPersistentTunnelShutdownReport {
    let report = await task.value
    storage = .stopped(report)
    return report
  }

  private var reportedState: ProductPersistentTunnelState {
    switch storage {
    case .idle: .idle
    case .starting: .starting
    case .active: .active
    case .stopping: .stopping
    case .stopped: .stopped
    }
  }
}
