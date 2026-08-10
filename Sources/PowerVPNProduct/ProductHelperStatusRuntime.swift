import PowerVPNCore

extension ProductReadinessRuntime {
  private static let helperProbeTimeoutMilliseconds = 2_000

  /// Reports passive helper state only. This path never constructs a live prober.
  public func helperStatus() -> ProductHelperStatusReport {
    helperStatus(
      observation: observer.observe(),
      liveProbePerformed: nil
    )
  }

  /// Performs one explicit, bounded, read-only helper reachability probe.
  /// The Core result owns the post-probe generation so this report cannot reuse
  /// a stale pre-probe `runs` value.
  public func helperStatusWithLiveProbe() async -> ProductHelperStatusReport {
    let observation = observer.observe()
    let probe = helperProbeFactory()
    let result = await probe.probe(
      timeoutMilliseconds: Self.helperProbeTimeoutMilliseconds
    )
    let directXPCStatus: DirectXPCStatus
    if !result.probePerformed {
      directXPCStatus = .notProbed
    } else if result.status == .reachable {
      directXPCStatus = .currentReachable
    } else {
      directXPCStatus = .currentUnreachable
    }
    let preflightSafe =
      result.status == .preflightBlocked
      ? false
      : (result.probePerformed || observation.directXPCPreflightSafe)
    return helperStatus(
      observation: ProductReadinessObservation(
        installedVersion: observation.installedVersion,
        installedBuild: observation.installedBuild,
        installedArchitectures: observation.installedArchitectures,
        officialGUIRunning: observation.officialGUIRunning,
        helperAvailable: observation.helperAvailable,
        generation: result.finalGeneration,
        directXPCStatus: directXPCStatus,
        directXPCPreflightSafe: preflightSafe,
        profileSource: observation.profileSource,
        resourceSource: observation.resourceSource,
        resourceCandidates: observation.resourceCandidates
      ),
      liveProbePerformed: result.probePerformed
    )
  }

  private func helperStatus(
    observation: ProductReadinessObservation,
    liveProbePerformed: Bool?
  ) -> ProductHelperStatusReport {
    let probeAvailable =
      observation.helperAvailable
      && observation.generation.launchdObserved
      && observation.directXPCPreflightSafe
    let state: ProductState
    let blocker: ProductBlocker?
    if !observation.helperAvailable {
      state = .blocked
      blocker = .helperUnavailable
    } else if !observation.generation.launchdObserved {
      state = .blocked
      blocker = .helperGenerationUnavailable
    } else if !observation.directXPCPreflightSafe {
      state = .blocked
      blocker = .directXPCPreflightUnsafe
    } else if observation.directXPCStatus == .currentReachable {
      state = .ready
      blocker = nil
    } else if observation.directXPCStatus == .currentUnreachable {
      state = .blocked
      blocker = .directXPCUnreachable
    } else {
      state = .degraded
      blocker = .directXPCNotProbed
    }
    return ProductHelperStatusReport(
      productState: state,
      helperAvailable: observation.helperAvailable,
      generation: ProductHelperGeneration(observation.generation),
      directXPCStatus: observation.directXPCStatus,
      liveProbePerformed: liveProbePerformed
        ?? (observation.directXPCStatus == .currentReachable
          || observation.directXPCStatus == .currentUnreachable),
      probeAvailable: probeAvailable,
      preflightSafe: observation.directXPCPreflightSafe,
      blocker: blocker
    )
  }
}
