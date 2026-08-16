import PowerVPNCore

package struct ProductM2CleanupCaptureAttempt: Sendable {
  let evidence: ProductM2CleanupEvidence
  let state: ProductM2CleanupCaptureState
  let captureInvoked: Bool

  package init(
    evidence: ProductM2CleanupEvidence,
    state: ProductM2CleanupCaptureState,
    captureInvoked: Bool
  ) {
    self.evidence = evidence
    self.state = state
    self.captureInvoked = captureInvoked
  }

  package init(
    before: NetworkCleanupSnapshot,
    after: NetworkCleanupSnapshot,
    startRequestSent: Bool
  ) {
    evidence = ProductM2CleanupEvidence(
      NetworkCleanupAssessment.assess(
        before: before,
        after: after,
        startRequestSent: startRequestSent
      ))
    state = Self.classify(after)
    captureInvoked = true
  }

  package static func measured(_ evidence: ProductM2CleanupEvidence) -> Self {
    precondition(evidence.complete)
    return Self(evidence: evidence, state: .measuredComplete, captureInvoked: true)
  }

  package static let unavailable = Self(
    evidence: .unavailable,
    state: .unavailable,
    captureInvoked: false
  )

  package static let deadlineExceeded = Self(
    evidence: .unavailable,
    state: .deadlineExceeded,
    captureInvoked: false
  )

  var retryReason: ProductM2CleanupCaptureRetryReason? {
    switch state {
    case .changedDuringCapture:
      return .changedDuringCapture
    case .helperProcessGenerationInconsistent:
      return .helperProcessGenerationInconsistent
    default:
      return nil
    }
  }

  private static func classify(
    _ snapshot: NetworkCleanupSnapshot
  ) -> ProductM2CleanupCaptureState {
    if snapshot.complete { return .measuredComplete }

    let failureStates = observationFailureStates(snapshot)
    if failureStates.contains(.commandFailed) { return .commandFailed }
    if failureStates.contains(.outputTooLarge) { return .outputTooLarge }
    if failureStates.contains(.invalidOutput) { return .invalidOutput }
    guard observedPrimitiveStatesConsistent(snapshot) else {
      return .structuralInconsistency
    }
    let helperChangeWasMeasured =
      snapshot.helperObservationState != .changedDuringCapture
      || snapshot.helperGeneration.exactInactive
      || snapshot.helperGeneration.exactRunning
    let onlyChanged =
      !failureStates.isEmpty
      && failureStates.allSatisfy({ $0 == .changedDuringCapture })
      && helperChangeWasMeasured
    if onlyChanged {
      return .changedDuringCapture
    }
    let helperChangeUnavailable =
      snapshot.helperObservationState == .changedDuringCapture
      && !helperChangeWasMeasured
    if helperChangeUnavailable {
      return .generationNotExact
    }

    guard allSubobservationsObserved(snapshot) else {
      return .structuralInconsistency
    }
    guard
      snapshot.helperGeneration.exactInactive
        || snapshot.helperGeneration.exactRunning
    else {
      return .generationNotExact
    }
    guard snapshot.vendorProcesses.guiAndUnrelatedHelpersAbsent else {
      return .vendorProcessResidue
    }

    // Every observable completeness term is now true except the private
    // helper-generation/vendor-process relation used by `snapshot.complete`.
    // No counts or process identities leave the package.
    return .helperProcessGenerationInconsistent
  }

  private static func observationFailureStates(
    _ snapshot: NetworkCleanupSnapshot
  ) -> [NetworkCleanupObservationState] {
    var states = [
      snapshot.helperObservationState,
      snapshot.surge.fingerprint.state,
      snapshot.defaultRoute.state,
      snapshot.dns.state,
      snapshot.interfaces.inventory.state,
    ]
    states.append(contentsOf: snapshot.ipv4Routes.primitiveObservationStates)
    states.append(contentsOf: snapshot.ipv6Routes.primitiveObservationStates)
    states.append(snapshot.vendorProcesses.fingerprint.state)
    return states.filter { $0 != .observed }
  }

  private static func observedPrimitiveStatesConsistent(
    _ snapshot: NetworkCleanupSnapshot
  ) -> Bool {
    (snapshot.surge.fingerprint.state != .observed || snapshot.surge.isObserved)
      && (snapshot.defaultRoute.state != .observed || snapshot.defaultRoute.isObserved)
      && (snapshot.dns.state != .observed || snapshot.dns.isObserved)
      && (snapshot.interfaces.inventory.state != .observed || snapshot.interfaces.isObserved)
      && snapshot.ipv4Routes.observedPrimitiveStatesConsistent
      && snapshot.ipv6Routes.observedPrimitiveStatesConsistent
      && (snapshot.vendorProcesses.fingerprint.state != .observed
        || snapshot.vendorProcesses.isObserved)
  }

  private static func allSubobservationsObserved(
    _ snapshot: NetworkCleanupSnapshot
  ) -> Bool {
    snapshot.helperObservationState == .observed
      && snapshot.surge.isObserved
      && snapshot.defaultRoute.isObserved
      && snapshot.dns.isObserved
      && snapshot.interfaces.isObserved
      && snapshot.ipv4Routes.isObserved
      && snapshot.ipv6Routes.isObserved
      && snapshot.vendorProcesses.isObserved
  }
}

struct ProductM2CleanupVerificationOutcome: Sendable {
  let evidence: ProductM2CleanupEvidence
  let state: ProductM2CleanupCaptureState
  let retryReason: ProductM2CleanupCaptureRetryReason?
  let attemptCount: Int
}

extension ProductM2CleanupRunner {
  func verifyCleanupBounded(
    baseline: ProductM2NetworkBaseline,
    networkWindow: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    startRequestSent: Bool,
    deadline: ProductM2StageDeadline
  ) async -> ProductM2CleanupVerificationOutcome {
    guard deadline.hasRemaining else {
      return outcome(from: .deadlineExceeded, retryReason: nil, attemptCount: 0)
    }

    let first = await cleanupCaptureAttempt(
      baseline: baseline,
      networkWindow: networkWindow,
      selectedRoutes: selectedRoutes,
      startRequestSent: startRequestSent,
      deadline: deadline
    )
    let firstAttemptCount = first.captureInvoked ? 1 : 0
    guard let retryReason = first.retryReason else {
      return outcome(from: first, retryReason: nil, attemptCount: firstAttemptCount)
    }
    guard deadline.hasRemaining else {
      return outcome(
        from: .deadlineExceeded,
        retryReason: retryReason,
        attemptCount: firstAttemptCount
      )
    }

    let second = await cleanupCaptureAttempt(
      baseline: baseline,
      networkWindow: networkWindow,
      selectedRoutes: selectedRoutes,
      startRequestSent: startRequestSent,
      deadline: deadline
    )
    let secondAttemptCount = firstAttemptCount + (second.captureInvoked ? 1 : 0)
    return outcome(
      from: second,
      retryReason: retryReason,
      attemptCount: secondAttemptCount
    )
  }

  private func cleanupCaptureAttempt(
    baseline: ProductM2NetworkBaseline,
    networkWindow: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    startRequestSent: Bool,
    deadline: ProductM2StageDeadline
  ) async -> ProductM2CleanupCaptureAttempt {
    let verifier = dependencies.verifyCleanup
    return await Task.detached {
      await verifier(
        baseline,
        networkWindow,
        selectedRoutes,
        startRequestSent,
        deadline
      )
    }.value
  }

  private func outcome(
    from attempt: ProductM2CleanupCaptureAttempt,
    retryReason: ProductM2CleanupCaptureRetryReason?,
    attemptCount: Int
  ) -> ProductM2CleanupVerificationOutcome {
    precondition((0...2).contains(attemptCount))
    return ProductM2CleanupVerificationOutcome(
      evidence: attempt.evidence,
      state: attempt.state,
      retryReason: retryReason,
      attemptCount: attemptCount
    )
  }
}
