package enum VendorXPCReachabilityStatus: String, Codable, Equatable, Sendable {
  case reachable
  case unreachable
  case preflightBlocked = "preflight_blocked"
  case timeout
  case cancelled
  case invalidTimeout = "invalid_timeout"
}

/// Value-free product evidence for one explicit, fixed `get_version` probe.
/// `probePerformed` is true only after the fixed transport was invoked.
package struct VendorXPCReachabilityResult: Equatable, Sendable {
  package let status: VendorXPCReachabilityStatus
  package let probePerformed: Bool
  package let transportAccepted: Bool
  package let helperGenerationRelation: VendorHelperGenerationRelation
  package let finalGeneration: VendorHelperGenerationSnapshot
  package let connectionCancelRequested: Bool

  package init(
    status: VendorXPCReachabilityStatus,
    probePerformed: Bool,
    transportAccepted: Bool,
    helperGenerationRelation: VendorHelperGenerationRelation,
    finalGeneration: VendorHelperGenerationSnapshot,
    connectionCancelRequested: Bool
  ) {
    self.status = status
    self.probePerformed = probePerformed
    self.transportAccepted = transportAccepted
    self.helperGenerationRelation = helperGenerationRelation
    self.finalGeneration = finalGeneration
    self.connectionCancelRequested = connectionCancelRequested
  }
}

package protocol VendorXPCReachabilityProbing: Sendable {
  func probe(timeoutMilliseconds: Int) async -> VendorXPCReachabilityResult
}

/// Explicit read-only reachability check for the fixed vendor charon service.
/// Construction is inert. `probe` performs only bounded local observations and
/// the exact two-field `get_version` request encoded by `RawVendorXPCTransport`.
package struct VendorXPCReachabilityProbe: VendorXPCReachabilityProbing, Sendable {
  private let transport: any VendorXPCTransporting
  private let generationObserver: any BoundedVendorHelperGenerationObserving
  private let preflightChecker: any BoundedVendorXPCPreflightChecking

  package init() {
    transport = RawVendorXPCTransport()
    generationObserver = InstalledBoundedVendorHelperGenerationObserver()
    preflightChecker = InstalledBoundedVendorXPCPreflightChecker()
  }

  init(
    transport: any VendorXPCTransporting,
    generationObserver: any BoundedVendorHelperGenerationObserving,
    preflightChecker: any BoundedVendorXPCPreflightChecking
  ) {
    self.transport = transport
    self.generationObserver = generationObserver
    self.preflightChecker = preflightChecker
  }

  package func probe(
    timeoutMilliseconds: Int = RawVendorXPCTransport.defaultTimeoutMilliseconds
  ) async -> VendorXPCReachabilityResult {
    guard RawVendorXPCTransport.validTimeoutMilliseconds.contains(timeoutMilliseconds) else {
      return immediate(.invalidTimeout)
    }
    guard !Task.isCancelled else { return immediate(.cancelled) }

    let before = await generationObserver.observe()
    guard !Task.isCancelled else { return immediate(.cancelled, generation: before) }

    let preflight = await preflightChecker.check(generation: before)
    guard !Task.isCancelled else { return immediate(.cancelled, generation: before) }
    guard preflight.safeToProbe else {
      return immediate(.preflightBlocked, generation: before)
    }

    let evidence = await transport.getVersion(
      timeoutMilliseconds: timeoutMilliseconds
    ) { peerPID in
      let current = await generationObserver.observe()
      return VendorReplyGenerationValidator.validate(
        before: before,
        current: current,
        peerPID: peerPID
      )
    }
    let after = await cancellationShieldedGenerationObservation()
    let generation = VendorHelperGenerationAssessment.assess(
      before: before,
      after: after,
      replyPeerGenerationValidated: evidence.replyPeerGenerationValidated
    )
    let generationAccepted =
      generation.relation == .launched
      || generation.relation == .launchedAndExited
    let accepted =
      evidence.accepted
      && generationAccepted
      && generation.replyPeerMatchesObservedGeneration
      && evidence.connectionCancelRequested

    let status: VendorXPCReachabilityStatus
    switch evidence.outcome {
    case .timeout: status = .timeout
    case .cancelled: status = .cancelled
    case .invalidTimeout: status = .invalidTimeout
    default: status = accepted ? .reachable : .unreachable
    }
    return VendorXPCReachabilityResult(
      status: status,
      probePerformed: true,
      transportAccepted: evidence.accepted,
      helperGenerationRelation: generation.relation,
      finalGeneration: after,
      connectionCancelRequested: evidence.connectionCancelRequested
    )
  }

  private func immediate(
    _ status: VendorXPCReachabilityStatus,
    generation: VendorHelperGenerationSnapshot = .unavailable
  ) -> VendorXPCReachabilityResult {
    VendorXPCReachabilityResult(
      status: status,
      probePerformed: false,
      transportAccepted: false,
      helperGenerationRelation: generation.exactInactive ? .inactive : .unavailable,
      finalGeneration: generation,
      connectionCancelRequested: false
    )
  }

  /// Cancellation must tear down XPC immediately, but the caller still needs
  /// one bounded post-attempt generation receipt rather than stale preflight
  /// state. The installed observer itself remains normally cancellable.
  private func cancellationShieldedGenerationObservation() async
    -> VendorHelperGenerationSnapshot
  {
    let observer = generationObserver
    return await Task.detached {
      await observer.observe()
    }.value
  }
}
