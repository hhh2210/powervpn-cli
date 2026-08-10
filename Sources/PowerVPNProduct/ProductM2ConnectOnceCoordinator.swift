import Foundation
import PowerVPNCore

package struct ProductM2ConnectOnceCoordinator: Sendable {
  let dependencies: ProductM2ConnectOnceDependencies

  package init(dependencies: ProductM2ConnectOnceDependencies) {
    self.dependencies = dependencies
  }

  package func run(
    _ request: ProductM2ConnectRequest
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
    guard dependencies.controlRuntimePreflightAccepted() else {
      execution.fail(.preflightBlocked, event: .preflightRejected, state: .blocked)
      return execution.report()
    }
    let coldGeneration = await dependencies.observeGeneration()
    guard coldGeneration.exactInactive,
      await dependencies.preflightAccepted(coldGeneration)
    else {
      execution.fail(.preflightBlocked, event: .preflightRejected, state: .blocked)
      return execution.report()
    }
    guard
      let baseline = await dependencies.captureNetworkBaseline(
        execution.networkWindow,
        nil
      )
    else {
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
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration
      )
    }

    execution.lastGoodState = .authenticating
    let acquisition = await dependencies.acquireAuthorization()
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
          authorizationLease: lease
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
      execution.fail(
        normalizedFailure == .cancelled ? .cancelled : .authorizationAcquisitionRejected,
        event: normalizedFailure == .cancelled ? .cancelled : .authorizationAcquisitionRejected,
        state: normalizedFailure == .cancelled ? .failed : .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration
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
        coldGeneration: coldGeneration
      )
    }
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    }

    let selection: ProductM2AuthorizedResourceSelection
    do {
      selection = try await authorizationLease.selectUnique(
        displayName: request.resourceDisplayName,
        requiredTargetIPv4: request.sshTarget.requiredTargetIPv4
      )
    } catch ProductM2AuthorizedResourceSelectionError.resourceNotFound {
      execution.fail(.resourceNotFound, event: .resourceNotFound, state: .blocked)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    } catch ProductM2AuthorizedResourceSelectionError.resourceAmbiguous {
      execution.fail(.resourceAmbiguous, event: .resourceAmbiguous, state: .blocked)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    } catch ProductM2AuthorizedResourceSelectionError.selectedRouteCoverageRejected {
      execution.fail(
        .selectedRouteCoverageRejected,
        event: .selectedRouteCoverageRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    } catch ProductM2AuthorizedResourceSelectionError.startSnapshotRejected {
      execution.fail(
        .startSnapshotRejected,
        event: .startSnapshotRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    } catch {
      execution.fail(
        .resourceCatalogRejected,
        event: .resourceCatalogRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    }

    execution.lastGoodState = .ready
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    }

    let selectedRoutes = selection.selectedRoutes

    guard
      let preStartBaseline = await dependencies.captureNetworkBaseline(
        execution.networkWindow,
        selectedRoutes
      )
    else {
      execution.fail(
        .networkBaselineUnavailable,
        event: .networkBaselineUnavailable,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease
      )
    }
    guard dependencies.baselineStable(baseline, preStartBaseline) else {
      execution.fail(
        .networkBaselineChanged,
        event: .networkBaselineChanged,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: preStartBaseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selectedRoutes
      )
    }
    let recheckedGeneration = await dependencies.observeGeneration()
    guard
      ProductM2GenerationFence.sameColdGeneration(
        coldGeneration,
        recheckedGeneration
      ), await dependencies.preflightAccepted(recheckedGeneration)
    else {
      execution.fail(
        .generationFenceRejected,
        event: .generationFenceRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: preStartBaseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selectedRoutes
      )
    }
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: preStartBaseline,
        coldGeneration: coldGeneration,
        authorizationLease: authorizationLease,
        selectedRoutes: selectedRoutes
      )
    }

    return await startProveAndFinish(
      &execution,
      baseline: preStartBaseline,
      coldGeneration: coldGeneration,
      authorizationLease: authorizationLease,
      selection: selection
    )
  }

}
