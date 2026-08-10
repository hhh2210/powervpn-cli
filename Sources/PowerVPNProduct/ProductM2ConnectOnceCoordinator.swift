import Foundation
import PowerVPNCore
import PowerVPNPortal

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
    let portalLease: (any ProductM2PortalLeasing)?
    switch acquisition {
    case .acquired(let source, let lease):
      portalLease = lease
      execution.serverContactRequested = source == .nativePortal
      guard source == dependencies.authorizationSource else {
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
          portalLease: lease
        )
      }
      execution.authorizationAcquisition = .acquired
    case .rejected(let source, let failure, let contacted):
      portalLease = nil
      execution.serverContactRequested = contacted
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

    guard let portalLease else {
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
        portalLease: portalLease
      )
    }

    let selected: ProductResourceCandidate
    do {
      let candidates = try AuthenticatedPortalSnapshotMapper.map(portalLease.snapshot)
        .filter { $0.summary.displayName == request.resourceDisplayName }
      guard candidates.count == 1 else {
        let outcome: ProductM2ConnectOutcome =
          candidates.isEmpty ? .resourceNotFound : .resourceAmbiguous
        let event: ProductM2BadEvent =
          candidates.isEmpty ? .resourceNotFound : .resourceAmbiguous
        execution.fail(outcome, event: event, state: .blocked)
        return await finish(
          &execution,
          baseline: baseline,
          coldGeneration: coldGeneration,
          portalLease: portalLease
        )
      }
      selected = candidates[0]
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
        portalLease: portalLease
      )
    }

    execution.lastGoodState = .ready
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        portalLease: portalLease
      )
    }

    let selectedRoutes: VendorCharonSelectedRouteMatcher
    do {
      selectedRoutes = try selectedRouteMatcher(
        snapshot: portalLease.snapshot,
        handle: selected.summary.handle,
        requiredTargetIPv4: request.sshTarget.requiredTargetIPv4
      )
    } catch ProductM2NetworkGateError.selectedRouteCoverageRejected {
      execution.fail(
        .selectedRouteCoverageRejected,
        event: .selectedRouteCoverageRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        portalLease: portalLease
      )
    } catch {
      execution.fail(
        .startSnapshotRejected,
        event: .startSnapshotRejected,
        state: .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration,
        portalLease: portalLease
      )
    }

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
        portalLease: portalLease
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
        portalLease: portalLease,
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
        portalLease: portalLease,
        selectedRoutes: selectedRoutes
      )
    }
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: preStartBaseline,
        coldGeneration: coldGeneration,
        portalLease: portalLease,
        selectedRoutes: selectedRoutes
      )
    }

    return await startProveAndFinish(
      &execution,
      baseline: preStartBaseline,
      coldGeneration: coldGeneration,
      portalLease: portalLease,
      selected: selected,
      selectedRoutes: selectedRoutes
    )
  }

}
