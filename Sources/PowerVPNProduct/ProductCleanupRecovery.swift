import PowerVPNCore
import PowerVPNPortal

extension ProductCleanupRecoveryDependencies {
  package init(
    authorizationProvider: any ProductM2AuthorizedResourceProviding,
    generationObserver: any BoundedVendorHelperGenerationObserving =
      InstalledBoundedVendorHelperGenerationObserver(),
    networkObserver: any NetworkCleanupObserving = InstalledNetworkCleanupObserver(),
    preflightChecker: any BoundedVendorXPCPreflightChecking =
      InstalledBoundedVendorXPCPreflightChecker()
  ) {
    self.init(
      acquireMutationLease: ProductMutationLease.acquireCurrentMachine,
      authorizationSource: authorizationProvider.source,
      authorizationAvailabilityFailure: authorizationProvider.availabilityFailure,
      beginAuthorization: authorizationProvider.beginAcquire,
      observeGeneration: { deadline in
        guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
          return .unavailable
        }
        return await generationObserver.observe(timeoutMilliseconds: timeout)
      },
      captureNetwork: { window, routes, deadline in
        guard let timeout = deadline.remainingMilliseconds(cappedAt: 24_000) else {
          return .unavailable(.commandFailed)
        }
        return await networkObserver.capture(
          window: window,
          selectedRoutes: routes,
          timeoutMilliseconds: timeout
        )
      },
      checkPreflight: { generation, deadline in
        guard let timeout = deadline.remainingMilliseconds(cappedAt: 2_000) else {
          return Self.unavailablePreflight
        }
        return await preflightChecker.check(
          generation: generation,
          timeoutMilliseconds: timeout
        )
      }
    )
  }

  private static let unavailablePreflight = VendorXPCPreflightEvidence(
    guiProcessAbsent: false,
    helperProcessAbsent: false,
    otherVendorHelperProcessesAbsent: false,
    helperLaunchdInactive: false,
    dnsRecoveryFileAbsent: false,
    vendorLogRotationSafe: false
  )
}

private struct ProductClosedRecoveryAuthorization: Sendable {
  let source: ProductM2AuthorizationSource
  let routes: VendorCharonSelectedRouteMatcher?
  let close: ProductM2AuthorizationCloseReceipt
  let contacted: Bool
}

package struct ProductCleanupRecoveryRuntime: Sendable {
  package typealias CommitRecovered = @Sendable (ProductCleanupRecoveryReport) -> Bool

  private let dependencies: ProductCleanupRecoveryDependencies

  package init(configuration: PowerVPNTargetsConfiguration) {
    let provider = ProductM2PortalAdapter { _ in
      await PortalLoginRuntime.acquire(configuration: configuration)
    }
    dependencies = ProductCleanupRecoveryDependencies(authorizationProvider: provider)
  }

  package init(dependencies: ProductCleanupRecoveryDependencies) {
    self.dependencies = dependencies
  }

  package func run(
    _ request: ProductCleanupRecoveryRequest,
    budget: ProductM2AbsoluteBudget = .start(),
    commitRecovered: CommitRecovered = { _ in true }
  ) async -> ProductCleanupRecoveryReport {
    let mutationLease: any ProductMutationLeaseHolding
    do {
      mutationLease = try dependencies.acquireMutationLease()
    } catch {
      return report(.mutationLeaseUnavailable, mutationLeaseAcquired: false)
    }
    defer { withExtendedLifetime(mutationLease) {} }

    if Task.isCancelled { return report(.cancelled) }
    if let unavailable = dependencies.authorizationAvailabilityFailure {
      return report(.authorizationUnavailable, authorizationFailure: unavailable)
    }
    let initialGeneration = await dependencies.observeGeneration(budget.work)
    guard !Task.isCancelled, budget.work.hasRemaining else {
      return report(.cancelled)
    }
    let initialPreflight = await dependencies.checkPreflight(initialGeneration, budget.work)
    guard !Task.isCancelled, budget.work.hasRemaining else {
      return report(.cancelled)
    }
    guard initialGeneration.exactInactive, initialPreflight.safeToProbe else {
      return report(.preflightRejected)
    }

    let measured: ProductCleanupRecoveryReport
    switch await acquireAuthorization(budget.authorization) {
    case .rejected(let source, let failure, let close):
      measured = report(
        failure == .cancelled ? .cancelled : .authorizationRejected,
        source: source,
        authorizationFailure: failure,
        close: close
      )
    case .acquired(let source, let lease, let contacted):
      let authorization = await closeAuthorization(
        request,
        source: source,
        lease: lease,
        contacted: contacted,
        budget: budget
      )
      measured = await measure(
        authorization,
        initialGeneration: initialGeneration,
        budget: budget
      )
    }
    guard measured.permitsReconnect else { return measured }
    guard !Task.isCancelled else {
      return ProductCleanupRecoveryReport(cancelled: measured)
    }
    guard commitRecovered(measured) else {
      return Task.isCancelled
        ? ProductCleanupRecoveryReport(cancelled: measured)
        : ProductCleanupRecoveryReport(persistenceRejected: measured)
    }
    return measured
  }

  private func closeAuthorization(
    _ request: ProductCleanupRecoveryRequest,
    source: ProductM2AuthorizationSource,
    lease: ProductM2AuthorizedResourceLease,
    contacted: Bool,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductClosedRecoveryAuthorization {
    let routes: VendorCharonSelectedRouteMatcher?
    do {
      guard source == dependencies.authorizationSource,
        lease.source == source,
        let target = request.sshTarget.resolvedTargetIPv4
      else { throw ProductM2AuthorizedResourceSelectionError.invalidSelection }
      routes = try await lease.selectUnique(
        displayName: request.resourceDisplayName,
        requiredTargetIPv4: target
      ).selectedRoutes
    } catch {
      routes = nil
    }
    let close = await lease.closeAndErase(deadline: budget.authorization.cleanup)
    return ProductClosedRecoveryAuthorization(
      source: source,
      routes: routes,
      close: close,
      contacted: contacted || close.serverContactRequested
    )
  }

  private func measure(
    _ authorization: ProductClosedRecoveryAuthorization,
    initialGeneration: VendorHelperGenerationSnapshot,
    budget: ProductM2AbsoluteBudget
  ) async -> ProductCleanupRecoveryReport {
    guard authorization.close.outcome == .accepted,
      authorization.close.ownedMaterialErased
    else { return report(.authorizationCloseRejected, authorization: authorization) }
    guard let routes = authorization.routes else {
      return report(
        Task.isCancelled ? .cancelled : .selectionRejected,
        authorization: authorization
      )
    }
    guard !Task.isCancelled, budget.verification.hasRemaining else {
      return report(
        Task.isCancelled ? .cancelled : .captureUnavailable,
        authorization: authorization
      )
    }

    let window = NetworkCleanupCaptureWindow()
    let first = await dependencies.captureNetwork(window, routes, budget.verification)
    guard !Task.isCancelled, budget.verification.hasRemaining else {
      return report(
        Task.isCancelled ? .cancelled : .captureUnavailable,
        authorization: authorization,
        attempts: 1
      )
    }
    let second = await dependencies.captureNetwork(window, routes, budget.verification)
    let assessment = NetworkColdRecoveryAssessment(
      initialGeneration: initialGeneration,
      first: first,
      second: second
    )
    guard !Task.isCancelled, budget.verification.hasRemaining else {
      return report(
        Task.isCancelled ? .cancelled : .captureUnavailable,
        authorization: authorization,
        assessment: assessment,
        attempts: 2
      )
    }
    let preflight = await dependencies.checkPreflight(
      second.helperGeneration,
      budget.verification
    )
    guard !Task.isCancelled, budget.verification.hasRemaining else {
      return report(
        Task.isCancelled ? .cancelled : .captureUnavailable,
        authorization: authorization,
        assessment: assessment,
        attempts: 2
      )
    }
    let failure: ProductCleanupRecoveryFailure? =
      !assessment.passed
      ? .coldBaselineRejected
      : (preflight.safeToProbe ? nil : .preflightRejected)
    return report(
      failure,
      authorization: authorization,
      assessment: assessment,
      attempts: 2,
      preflightSafe: preflight.safeToProbe
    )
  }

  private func acquireAuthorization(
    _ budget: ProductM2AuthorizationBudget
  ) async -> ProductM2AuthorizedResourceAcquisition {
    let attempt = dependencies.beginAuthorization(budget)
    return await withTaskCancellationHandler {
      await attempt.result()
    } onCancel: {
      attempt.cancel()
    }
  }

  private func report(
    _ failure: ProductCleanupRecoveryFailure?,
    source: ProductM2AuthorizationSource? = nil,
    authorizationFailure: ProductM2AuthorizationFailure? = nil,
    close: ProductM2AuthorizationCloseReceipt? = nil,
    authorization: ProductClosedRecoveryAuthorization? = nil,
    assessment: NetworkColdRecoveryAssessment? = nil,
    attempts: Int = 0,
    preflightSafe: Bool = false,
    mutationLeaseAcquired: Bool = true
  ) -> ProductCleanupRecoveryReport {
    ProductCleanupRecoveryReport(
      failure: failure,
      source: source ?? authorization?.source ?? dependencies.authorizationSource,
      authorizationFailure: authorizationFailure,
      close: close ?? authorization?.close,
      contacted: authorization?.contacted ?? false,
      assessment: assessment,
      attempts: attempts,
      preflightSafe: preflightSafe,
      mutationLeaseAcquired: mutationLeaseAcquired
    )
  }
}
