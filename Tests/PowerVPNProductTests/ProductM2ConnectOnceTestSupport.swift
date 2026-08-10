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

actor ProductM2TestPortalLease: ProductM2PortalLeasing {
  nonisolated let snapshot: AuthenticatedPortalSnapshot
  private let trace: ProductM2TestTrace
  private let logoutStatus: PortalLeaseLogoutStatus

  init(
    snapshot: AuthenticatedPortalSnapshot,
    trace: ProductM2TestTrace,
    logoutStatus: PortalLeaseLogoutStatus
  ) {
    self.snapshot = snapshot
    self.trace = trace
    self.logoutStatus = logoutStatus
  }

  func logoutAndErase() async -> PortalLeaseLogoutStatus {
    trace.record("logout")
    return logoutStatus
  }
}

func productM2TestDependencies(
  snapshot: AuthenticatedPortalSnapshot,
  trace: ProductM2TestTrace,
  plan: ProductM2TestControlPlan = .acknowledged,
  baselineStable: Bool = true,
  activeNetwork: ProductM2ActiveNetworkEvidence = m2ProvenActiveNetwork,
  sshProof: ProductM2SSHProofOutcome = .proven,
  sshEvidenceTarget: ProductM2SSHTarget? = nil,
  cleanup: ProductM2CleanupEvidence = m2CompleteCleanup,
  logout: PortalLeaseLogoutStatus = .accepted,
  controlRuntimePreflightAccepted: Bool = true,
  cancelDuringAcquire: Bool = false,
  cancelDuringSSH: Bool = false
) -> ProductM2ConnectOnceDependencies {
  let lease = ProductM2TestPortalLease(
    snapshot: snapshot,
    trace: trace,
    logoutStatus: logout
  )
  return ProductM2ConnectOnceDependencies(
    controlRuntimePreflightAccepted: {
      trace.record("session_preflight")
      return controlRuntimePreflightAccepted
    },
    observeGeneration: trace.observeGeneration,
    preflightAccepted: { _ in trace.preflight() },
    captureNetworkBaseline: { window, selectedRoutes in
      trace.nextBaseline(window: window, selectedRoutes: selectedRoutes)
    },
    baselineStable: { _, _ in
      trace.record("baseline_stable")
      return baselineStable
    },
    assessActiveConnection: { _, _ in
      trace.record("active_assessment")
      return activeNetwork
    },
    authorizationSource: .nativePortal,
    acquireAuthorization: {
      trace.record("acquire")
      if cancelDuringAcquire { withUnsafeCurrentTask { $0?.cancel() } }
      return .acquired(source: .nativePortal, lease: lease)
    },
    control: productM2TestControl(trace: trace, plan: plan),
    proveFreshSSH: { target in
      trace.record("ssh")
      if cancelDuringSSH { withUnsafeCurrentTask { $0?.cancel() } }
      return m2SSHEvidence(sshProof, target: sshEvidenceTarget ?? target)
    },
    verifyCleanup: { baseline, window, selectedRoutes, startRequestSent in
      trace.markVerified(
        baseline,
        window: window,
        selectedRoutes: selectedRoutes,
        startRequestSent: startRequestSent
      )
      return cleanup
    }
  )
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

let m2ColdGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: false, inactiveConfirmed: true,
  activeCount: 0, pid: nil, runs: 19)

let m2RunningGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: true, inactiveConfirmed: false,
  activeCount: 1, pid: 41, runs: 20)

let m2ExitedGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: false, inactiveConfirmed: true,
  activeCount: 0, pid: nil, runs: 20)

let m2UnavailableGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: false, running: false, inactiveConfirmed: false,
  activeCount: nil, pid: nil, runs: nil)

func m2EventIndex(_ event: String, in events: [String]) -> Int {
  events.firstIndex(of: event) ?? Int.max
}
