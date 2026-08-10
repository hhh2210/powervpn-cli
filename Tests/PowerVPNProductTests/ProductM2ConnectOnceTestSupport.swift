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

  init(
    generation: VendorHelperGenerationSnapshot = m2ColdGeneration,
    baselines: [ProductM2NetworkBaseline] = [
      ProductM2NetworkBaseline(), ProductM2NetworkBaseline(),
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

  func observeGeneration() -> VendorHelperGenerationSnapshot {
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

  func nextBaseline() -> ProductM2NetworkBaseline? {
    lock.withLock {
      storedEvents.append("baseline")
      return storedBaselines.isEmpty ? nil : storedBaselines.removeFirst()
    }
  }

  func markVerified(_ baseline: ProductM2NetworkBaseline) {
    lock.withLock {
      storedEvents.append("verify")
      verifiedBaseline = baseline.identifier
    }
  }

  var events: [String] { lock.withLock { storedEvents } }
  var verifiedBaselineID: UUID? { lock.withLock { verifiedBaseline } }

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

struct ProductM2TestControlPlan: Sendable {
  let startOutcome: ProductM2ControlOutcome
  let startRequestSent: Bool
  let retainLease: Bool
  let generationAfterBegin: VendorHelperGenerationSnapshot
  let stopOutcome: ProductM2ControlOutcome
  let stopRequestSent: Bool

  static let acknowledged = Self(
    startOutcome: .transportAcknowledged,
    startRequestSent: true,
    retainLease: true,
    generationAfterBegin: m2RunningGeneration,
    stopOutcome: .transportAcknowledged,
    stopRequestSent: true
  )

  static func noLease(
    generation: VendorHelperGenerationSnapshot
  ) -> Self {
    Self(
      startOutcome: .timeout,
      startRequestSent: true,
      retainLease: false,
      generationAfterBegin: generation,
      stopOutcome: .notAttempted,
      stopRequestSent: false
    )
  }

  static func acknowledgedStop(
    outcome: ProductM2ControlOutcome,
    requestSent: Bool
  ) -> Self {
    Self(
      startOutcome: .transportAcknowledged,
      startRequestSent: true,
      retainLease: true,
      generationAfterBegin: m2RunningGeneration,
      stopOutcome: outcome,
      stopRequestSent: requestSent
    )
  }
}

func productM2TestControl(
  trace: ProductM2TestTrace,
  plan: ProductM2TestControlPlan
) -> ProductM2ControlAdapter {
  ProductM2ControlAdapter(
    beginStart: { _, validator in
      trace.record("begin_start")
      trace.setGeneration(plan.generationAfterBegin)
      let validatorAccepted =
        plan.startOutcome == .transportAcknowledged
        ? validator() : false
      let acknowledged =
        plan.startOutcome == .transportAcknowledged
        && validatorAccepted
      let receipt = m2Receipt(
        acknowledged
          ? .transportAcknowledged
          : plan.startOutcome == .transportAcknowledged
            ? .peerGenerationMismatch : plan.startOutcome,
        requestSent: plan.startRequestSent
      )
      let lease: ProductM2ControlLease? =
        acknowledged && plan.retainLease
        ? ProductM2ControlLease {
          trace.record("stop")
          return m2Receipt(plan.stopOutcome, requestSent: plan.stopRequestSent)
        } : nil
      return ProductM2PendingStart {
        trace.record("await_start")
        return ProductM2StartResult(receipt: receipt, lease: lease)
      }
    },
    emergencyStop: { predicate, validator in
      trace.record("emergency_stop")
      guard predicate() else { return .unsent(.preflightBlocked) }
      let accepted = validator()
      return m2Receipt(
        accepted ? .transportAcknowledged : .peerGenerationMismatch,
        requestSent: accepted
      )
    }
  )
}

func productM2TestDependencies(
  snapshot: AuthenticatedPortalSnapshot,
  trace: ProductM2TestTrace,
  plan: ProductM2TestControlPlan = .acknowledged,
  baselineStable: Bool = true,
  sshProof: ProductM2SSHProofOutcome = .proven,
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
    captureNetworkBaseline: { trace.nextBaseline() },
    baselineStable: { _, _ in
      trace.record("baseline_stable")
      return baselineStable
    },
    acquirePortal: {
      trace.record("acquire")
      if cancelDuringAcquire { withUnsafeCurrentTask { $0?.cancel() } }
      return .acquired(lease)
    },
    control: productM2TestControl(trace: trace, plan: plan),
    proveFreshSSH: { _ in
      trace.record("ssh")
      if cancelDuringSSH { withUnsafeCurrentTask { $0?.cancel() } }
      return sshProof
    },
    verifyCleanup: { baseline in
      trace.markVerified(baseline)
      return cleanup
    }
  )
}

func m2Receipt(
  _ outcome: ProductM2ControlOutcome,
  requestSent: Bool
) -> ProductM2ControlReceipt {
  ProductM2ControlReceipt(
    outcome: outcome,
    requestSent: requestSent,
    transportAcknowledged: outcome == .transportAcknowledged,
    peerGenerationValidated: outcome == .transportAcknowledged
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
      <SECURED-ROUTES name="direct"><ROUTE addr="10.1.2.3/24"/>
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

let m2CompleteCleanup = ProductM2CleanupEvidence(
  defaultRouteRestored: true,
  dnsRestored: true,
  interfacesRestored: true,
  utunRestored: true,
  surgeStateRestored: true,
  helperGenerationRestored: true
)

func m2EventIndex(_ event: String, in events: [String]) -> Int {
  events.firstIndex(of: event) ?? Int.max
}
