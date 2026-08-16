import Foundation
import PowerVPNCore

@testable import PowerVPNPortal
@testable import PowerVPNProduct

final class ProductM2TestTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedEvents: [String] = []
  private var storedGeneration: VendorHelperGenerationSnapshot
  private var storedBaselines: [ProductM2NetworkBaseline]
  private var verifiedBaseline: UUID?
  private var preflightResults: [Bool]
  private var storedNetworkWindowIDs: [ObjectIdentifier] = []
  private var storedMatcherPresence: [Bool] = []
  private var storedCleanupStartSent: [Bool] = []
  private var activeCaptureCallIndex = 0

  init(
    generation: VendorHelperGenerationSnapshot = m2ColdGeneration,
    baselines: [ProductM2NetworkBaseline] = [
      ProductM2NetworkBaseline(), ProductM2NetworkBaseline(),
      ProductM2NetworkBaseline(),
    ],
    preflightResults: [Bool] = [true, true]
  ) {
    storedGeneration = generation
    storedBaselines = baselines
    self.preflightResults = preflightResults
  }

  func record(_ event: String) {
    lock.withLock { storedEvents.append(event) }
  }

  func observeGeneration() async -> VendorHelperGenerationSnapshot {
    lock.withLock {
      storedEvents.append("observe_generation")
      return storedGeneration
    }
  }

  func setGeneration(_ generation: VendorHelperGenerationSnapshot) {
    lock.withLock { storedGeneration = generation }
  }

  func preflight() -> Bool {
    lock.withLock {
      storedEvents.append("preflight")
      return preflightResults.isEmpty ? false : preflightResults.removeFirst()
    }
  }

  func nextBaseline(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?
  ) -> ProductM2NetworkBaseline? {
    lock.withLock {
      storedEvents.append("baseline")
      storedNetworkWindowIDs.append(ObjectIdentifier(window))
      storedMatcherPresence.append(selectedRoutes != nil)
      return storedBaselines.isEmpty ? nil : storedBaselines.removeFirst()
    }
  }

  /// Capture accessor for the shared connect-once dependencies. The M2 flow
  /// captures in a fixed order (cold, pre-start, active), so an active-capture
  /// override applies from the third capture on; earlier captures keep drawing
  /// synthetic baselines.
  func nextCaptureOutcome(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    activeOverride: ProductM2ActiveCaptureOutcome?
  ) -> ProductM2ActiveCaptureOutcome {
    lock.withLock {
      storedEvents.append("baseline")
      storedNetworkWindowIDs.append(ObjectIdentifier(window))
      storedMatcherPresence.append(selectedRoutes != nil)
      activeCaptureCallIndex += 1
      if let activeOverride, activeCaptureCallIndex >= 3 {
        return activeOverride
      }
      let baseline = storedBaselines.isEmpty ? nil : storedBaselines.removeFirst()
      return ProductM2ActiveCaptureOutcome(baseline: baseline)
    }
  }

  func markVerified(
    _ baseline: ProductM2NetworkBaseline,
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    startRequestSent: Bool
  ) {
    lock.withLock {
      storedEvents.append("verify")
      verifiedBaseline = baseline.identifier
      storedNetworkWindowIDs.append(ObjectIdentifier(window))
      storedMatcherPresence.append(selectedRoutes != nil)
      storedCleanupStartSent.append(startRequestSent)
    }
  }

  var events: [String] { lock.withLock { storedEvents } }
  var verifiedBaselineID: UUID? { lock.withLock { verifiedBaseline } }
  var networkWindowIDs: [ObjectIdentifier] { lock.withLock { storedNetworkWindowIDs } }
  var matcherPresence: [Bool] { lock.withLock { storedMatcherPresence } }
  var cleanupStartSent: [Bool] { lock.withLock { storedCleanupStartSent } }

  func count(_ event: String) -> Int {
    lock.withLock { storedEvents.count { $0 == event } }
  }
}

final class ProductM2TestMutationLease: ProductMutationLeaseHolding, @unchecked Sendable {}
final class ProductM2CleanupAttemptQueue: @unchecked Sendable {
  private let lock = NSLock()
  private var attempts: [ProductM2CleanupCaptureAttempt]

  init(_ attempts: [ProductM2CleanupCaptureAttempt]) {
    self.attempts = attempts
  }

  func next() -> ProductM2CleanupCaptureAttempt {
    lock.withLock {
      guard !attempts.isEmpty else { return .unavailable }
      return attempts.removeFirst()
    }
  }
}

func productM2TestDependencies(
  snapshot: AuthenticatedPortalSnapshot,
  trace: ProductM2TestTrace,
  plan: ProductM2TestControlPlan = .acknowledged,
  startEventSignatures: [String]? = nil,
  startReplySignatures: [String]? = nil,
  unexpectedEventSignature: [String]? = nil,
  routeActivationOutcome: ProductM2ControlOutcome = .transportAcknowledged,
  routeDeactivationOutcome: ProductM2ControlOutcome = .transportAcknowledged,
  routeActivationCompletionSource: ProductM2ControlCompletionSource = .submission,
  statusEventCountOperation: (@Sendable () -> Int)? = nil,
  baselineStable: Bool = true,
  activeNetwork: ProductM2ActiveNetworkEvidence = m2ProvenActiveNetwork,
  sshProof: ProductM2SSHProofOutcome = .proven,
  sshEvidenceTarget: ProductM2SSHTarget? = nil,
  cleanup: ProductM2CleanupEvidence = m2CompleteCleanup,
  cleanupAttempts: [ProductM2CleanupCaptureAttempt]? = nil,
  logout: ProductM2AuthorizationCloseOutcome = .accepted,
  dependencyAuthorizationSource: ProductM2AuthorizationSource = .nativePortal,
  acquisitionAuthorizationSource: ProductM2AuthorizationSource = .nativePortal,
  leaseAuthorizationSource: ProductM2AuthorizationSource = .nativePortal,
  activeCaptureOutcome: ProductM2ActiveCaptureOutcome? = nil,
  authorizationPrepare: ProductM2AuthorizedResourceLease.Prepare? = nil,
  controlRuntimePreflightAccepted: Bool = true,
  cancelDuringAcquire: Bool = false,
  cancelDuringSSH: Bool = false,
  cancelDuringActiveCapture: Bool = false,
  generationObservationHonorsCancellation: Bool = false,
  beginAuthorizationOverride:
    (@Sendable (ProductM2AuthorizationBudget) -> ProductM2AuthorizationAttempt)? = nil,
  onAuthorizationClose: @escaping @Sendable (ProductM2StageDeadline) -> Void = { _ in },
  onCaptureBaseline:
    @escaping @Sendable (
      VendorCharonSelectedRouteMatcher?,
      ProductM2NetworkBaseline?,
      ProductM2StageDeadline
    ) -> Void = { _, _, _ in },
  onProveFreshSSH: @escaping @Sendable (ProductM2StageDeadline) -> Void = { _ in },
  onVerifyCleanup: @escaping @Sendable (ProductM2StageDeadline) -> Void = { _ in },
  onBeginStart: @escaping @Sendable (Int) -> Void = { _ in },
  onAwaitStart: @escaping @Sendable () -> Void = {},
  onStop: @escaping @Sendable (Int) -> Void = { _ in },
  onEmergencyStop: @escaping @Sendable (Int) -> Void = { _ in }
) -> ProductM2ConnectOnceDependencies {
  let defaultCleanupAttempt = ProductM2CleanupCaptureAttempt(
    evidence: cleanup,
    state: cleanup.complete ? .measuredComplete : .unavailable,
    captureInvoked: true
  )
  let cleanupAttemptQueue = ProductM2CleanupAttemptQueue(
    cleanupAttempts ?? [defaultCleanupAttempt]
  )
  let lease = ProductM2AuthorizedResourceLease(
    source: leaseAuthorizationSource,
    catalog: {
      try ProductM2PortalAdapter.catalog(snapshot: snapshot)
    },
    prepare: { handle, requiredTargetIPv4 in
      if let authorizationPrepare {
        return try authorizationPrepare(handle, requiredTargetIPv4)
      }
      return try ProductM2PortalAdapter.prepare(
        snapshot: snapshot,
        handle: handle,
        requiredTargetIPv4: requiredTargetIPv4
      )
    },
    eraseOwnedMaterial: {
      trace.record("erase_authorization")
      snapshot.erase()
      return snapshot.isErased
    },
    close: { deadline in
      trace.record("logout")
      onAuthorizationClose(deadline)
      return ProductM2AuthorizationCloseReceipt(
        outcome: logout,
        ownedMaterialErased: snapshot.isErased,
        sourceCloseRequested: true,
        serverContactRequested: false
      )
    }
  )
  return ProductM2ConnectOnceDependencies(
    acquireMutationLease: {
      trace.record("mutation_lease")
      return ProductM2TestMutationLease()
    },
    controlRuntimePreflightAccepted: {
      trace.record("session_preflight")
      return controlRuntimePreflightAccepted
    },
    observeGeneration: { _ in
      if generationObservationHonorsCancellation, Task.isCancelled {
        trace.record("cancelled_observe_generation")
        return m2UnavailableGeneration
      }
      return await trace.observeGeneration()
    },
    preflightAccepted: { _, _ in trace.preflight() },
    captureNetworkBaseline: { window, selectedRoutes, deadline in
      let result = trace.nextCaptureOutcome(
        window: window,
        selectedRoutes: selectedRoutes,
        activeOverride: activeCaptureOutcome
      )
      onCaptureBaseline(selectedRoutes, result.baseline, deadline)
      if cancelDuringActiveCapture, trace.count("baseline") >= 3 {
        withUnsafeCurrentTask { $0?.cancel() }
      }
      return result
    },
    baselineStable: { _, _ in
      trace.record("baseline_stable")
      return baselineStable
    },
    assessActiveConnection: { _, _ in
      trace.record("active_assessment")
      return activeNetwork
    },
    authorizationSource: dependencyAuthorizationSource,
    beginAuthorization: beginAuthorizationOverride ?? { _ in
      ProductM2AuthorizationAttempt(
        source: acquisitionAuthorizationSource,
        operation: {
          trace.record("acquire")
          if cancelDuringAcquire { withUnsafeCurrentTask { $0?.cancel() } }
          return .acquired(
            source: acquisitionAuthorizationSource,
            lease: lease,
            serverContactRequested: true
          )
        },
        cancel: { trace.record("cancel_acquire") }
      )
    },
    control: productM2TestControl(
      trace: trace,
      plan: plan,
      startEventSignatures: startEventSignatures,
      startReplySignatures: startReplySignatures,
      unexpectedEventSignature: unexpectedEventSignature,
      routeActivationOutcome: routeActivationOutcome,
      routeDeactivationOutcome: routeDeactivationOutcome,
      routeActivationCompletionSource: routeActivationCompletionSource,
      statusEventCountOperation: statusEventCountOperation,
      onBeginStart: onBeginStart,
      onAwaitStart: onAwaitStart,
      onStop: onStop,
      onEmergencyStop: onEmergencyStop
    ),
    proveFreshSSH: { target, deadline in
      trace.record("ssh")
      onProveFreshSSH(deadline)
      if cancelDuringSSH { withUnsafeCurrentTask { $0?.cancel() } }
      return m2SSHEvidence(sshProof, target: sshEvidenceTarget ?? target)
    },
    verifyCleanup: { baseline, window, selectedRoutes, startRequestSent, deadline in
      onVerifyCleanup(deadline)
      trace.markVerified(
        baseline,
        window: window,
        selectedRoutes: selectedRoutes,
        startRequestSent: startRequestSent
      )
      return cleanupAttemptQueue.next()
    }
  )
}

func m2TestBudget() -> ProductM2AbsoluteBudget {
  .start()
}

extension ProductM2ConnectOnceCoordinator {
  func run(
    _ request: ProductM2ConnectRequest
  ) async -> ProductM2ConnectReport {
    await run(request, budget: m2TestBudget())
  }
}

func m2ResourceXML(_ displayNames: [String]) -> String {
  let resources = displayNames.map { name in
    """
    <NC_RESOURCE status="1" mapid="resource-map"><TUNNEL tunnel-name="\(name)"
      authority="7" status="9" negotiate-mode="3"><IKE family="4">
      <CLIENT id="helper-session-material"/><SERVER port="500"/>
      <ISAKMP-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="null" hash="null"
        life-time="3600"/></TRANSFORMS></PROPOSAL></ISAKMP-SA>
      <IPSEC-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="aes256" hash="sha256"
        life-time="1800"/></TRANSFORMS></PROPOSAL></IPSEC-SA>
      <PSK key="psk-material"/><EXTENSIONS><PRIVATE-IP addr="10.10.10.4"/>
      <SECURED-ROUTES name="direct"><ROUTE addr="11.11.0.0/16"/>
      </SECURED-ROUTES></EXTENSIONS></IKE></TUNNEL></NC_RESOURCE>
    """
  }.joined()
  return "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/><RESOURCE_LIST>"
    + resources + "</RESOURCE_LIST></INTERGRATION_INFO></ROOT>"
}

func m2SingleResourceMultiTunnelXML(_ displayNames: [String]) -> String {
  let tunnels = displayNames.map { name in
    """
    <TUNNEL tunnel-name="\(name)" authority="7" status="9" negotiate-mode="3">
      <IKE family="4"><CLIENT id="helper-session-material"/><SERVER port="500"/>
        <ISAKMP-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="null" hash="null"
          life-time="3600"/></TRANSFORMS></PROPOSAL></ISAKMP-SA>
        <IPSEC-SA><PROPOSAL><TRANSFORMS><TRANSFORM enc="aes256" hash="sha256"
          life-time="1800"/></TRANSFORMS></PROPOSAL></IPSEC-SA>
        <PSK key="psk-material"/><EXTENSIONS><PRIVATE-IP addr="10.10.10.4"/>
          <SECURED-ROUTES name="direct"><ROUTE addr="11.11.0.0/16"/>
          </SECURED-ROUTES>
        </EXTENSIONS>
      </IKE>
    </TUNNEL>
    """
  }.joined()
  return "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/><RESOURCE_LIST>"
    + "<NC_RESOURCE status=\"1\" mapid=\"resource-map\">\(tunnels)</NC_RESOURCE>"
    + "</RESOURCE_LIST></INTERGRATION_INFO></ROOT>"
}

let m2ColdGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: false, inactiveConfirmed: true,
  activeCount: 0, pid: nil, runs: 19)

let m2RunningGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: true, inactiveConfirmed: false,
  activeCount: 1, pid: 41, runs: 20)

let m2RestartedGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: true, inactiveConfirmed: false,
  activeCount: 1, pid: 43, runs: 22)

let m2ExitedGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: false, inactiveConfirmed: true,
  activeCount: 0, pid: nil, runs: 20)

let m2UnavailableGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: false, running: false, inactiveConfirmed: false,
  activeCount: nil, pid: nil, runs: nil)

func m2EventIndex(_ event: String, in events: [String]) -> Int {
  events.firstIndex(of: event) ?? Int.max
}
