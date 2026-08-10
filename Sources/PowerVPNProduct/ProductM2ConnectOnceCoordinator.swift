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
      networkWindow: NetworkCleanupCaptureWindow()
    )
    guard dependencies.controlRuntimePreflightAccepted() else {
      execution.fail(.preflightBlocked, event: .preflightRejected, state: .blocked)
      return execution.report()
    }
    let coldGeneration = dependencies.observeGeneration()
    guard coldGeneration.exactInactive,
      dependencies.preflightAccepted(coldGeneration)
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
    if Task.isCancelled {
      execution.fail(.cancelled, event: .cancelled, state: .failed)
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration
      )
    }

    execution.lastGoodState = .authenticating
    let acquisition = await dependencies.acquirePortal()
    let portalLease: (any ProductM2PortalLeasing)?
    switch acquisition {
    case .acquired(let lease):
      portalLease = lease
      execution.portalAcquisition = .acquired
      execution.serverContactRequested = true
    case .rejected(let status, let contacted):
      portalLease = nil
      execution.serverContactRequested = contacted
      execution.portalAcquisition = status == .cancelled ? .cancelled : .rejected
      execution.fail(
        status == .cancelled ? .cancelled : .portalAcquisitionRejected,
        event: status == .cancelled ? .cancelled : .portalAcquisitionRejected,
        state: status == .cancelled ? .failed : .blocked
      )
      return await finish(
        &execution,
        baseline: baseline,
        coldGeneration: coldGeneration
      )
    }

    guard let portalLease else {
      execution.fail(
        .portalAcquisitionRejected,
        event: .portalAcquisitionRejected,
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
    let recheckedGeneration = dependencies.observeGeneration()
    guard
      ProductM2GenerationFence.sameColdGeneration(
        coldGeneration,
        recheckedGeneration
      ), dependencies.preflightAccepted(recheckedGeneration)
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
