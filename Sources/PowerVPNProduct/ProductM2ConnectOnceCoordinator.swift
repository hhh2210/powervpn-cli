import Foundation
import PowerVPNCore

package struct ProductM2ConnectOnceCoordinator: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies

  package init(dependencies: ProductM2ConnectOnceDependencies) {
    self.dependencies = dependencies
  }

  package func run(
    _ request: ProductM2ConnectRequest,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductM2ConnectReport {
    var execution = ProductM2Execution(
      request: request,
      networkWindow: NetworkCleanupCaptureWindow(),
      authorizationSource: dependencies.authorizationSource
    )
    if let failure = dependencies.authorizationAvailabilityFailure {
      execution.authorizationAcquisition = .rejected
      execution.authorizationFailure = failure
      execution.fail(
        .authorizationAcquisitionRejected,
        event: .authorizationAcquisitionRejected,
        state: .blocked
      )
      return execution.report()
    }
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return execution.report()
    }
    guard dependencies.controlRuntimePreflightAccepted() else {
      execution.fail(.preflightBlocked, event: .preflightRejected, state: .blocked)
      return execution.report()
    }
    let coldGeneration = await dependencies.observeGeneration(budget.work)
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return execution.report()
    }
    guard coldGeneration.exactInactive else {
      execution.fail(.preflightBlocked, event: .preflightRejected, state: .blocked)
      return execution.report()
    }
    let preflightAccepted = await dependencies.preflightAccepted(coldGeneration, budget.work)
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return execution.report()
    }
    guard preflightAccepted else {
      execution.fail(.preflightBlocked, event: .preflightRejected, state: .blocked)
      return execution.report()
    }
    guard
      let baseline = await dependencies.captureNetworkBaseline(
        execution.networkWindow,
        nil,
        budget.work
      )
    else {
      if applyWorkAbortIfNeeded(&execution, budget: budget) {
        return execution.report()
      }
      execution.fail(
        .networkBaselineUnavailable,
        event: .networkBaselineUnavailable,
        state: .blocked
      )
      return execution.report()
    }
    if let capturedGeneration = baseline.helperGeneration,
      !ProductM2GenerationFence.sameColdGeneration(
        coldGeneration,
        capturedGeneration
      )
    {
      execution.fail(
        .generationFenceRejected,
        event: .generationFenceRejected,
        state: .blocked
      )
      return execution.report()
    }
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        budget: budget
      )
    }

    execution.lastGoodState = .authenticating
    let acquisitionAttempt = dependencies.beginAuthorization(budget.authorization)
    let acquisition = await withTaskCancellationHandler {
      await acquisitionAttempt.result()
    } onCancel: {
      acquisitionAttempt.cancel()
    }
    let authorizationLease: ProductM2AuthorizedResourceLease?
    switch acquisition {
    case .acquired(let source, let lease, let contacted):
      authorizationLease = lease
      execution.serverContactRequested = contacted
      execution.authorizationOwnedMaterialErased = false
      guard source == dependencies.authorizationSource,
        lease.source == source
      else {
        execution.authorizationAcquisition = .rejected
        execution.authorizationFailure = .sourceMismatch
        execution.fail(
          .authorizationAcquisitionRejected,
          event: .authorizationAcquisitionRejected,
          state: .blocked
        )
        return await finish(
          &execution,
          baseline: baseline,
          coldGeneration: coldGeneration,
          authorizationLease: lease,
          budget: budget
        )
      }
      execution.authorizationAcquisition = .acquired
    case .rejected(let source, let failure, let cleanup):
      authorizationLease = nil
      execution.serverContactRequested = cleanup.serverContactRequested
      execution.authorizationOwnedMaterialErased = cleanup.ownedMaterialErased
      execution.authorizationClose = cleanup.outcome
      let normalizedFailure =
        source == dependencies.authorizationSource ? failure : .sourceMismatch
      execution.authorizationAcquisition =
        normalizedFailure == .cancelled ? .cancelled : .rejected
      execution.authorizationFailure = normalizedFailure
      let deadlineExceeded = normalizedFailure == .timedOut || !budget.work.hasRemaining
      execution.fail(
        deadlineExceeded
          ? .deadlineExceeded
          : (normalizedFailure == .cancelled ? .cancelled : .authorizationAcquisitionRejected),
        event: deadlineExceeded
          ? .deadlineExceeded
          : (normalizedFailure == .cancelled ? .cancelled : .authorizationAcquisitionRejected),
        state: deadlineExceeded || normalizedFailure == .cancelled ? .failed : .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        budget: budget
      )
    }

    guard let authorizationLease else {
      execution.fail(
        .authorizationAcquisitionRejected,
        event: .authorizationAcquisitionRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        budget: budget
      )
    }
    if applyWorkAbortIfNeeded(&execution, budget: budget) {
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        budget: budget
      )
    }

    return await selectPrepareAndRun(
      &execution,
      baseline: baseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      budget: budget
    )
  }

}
