import Foundation

@testable import PowerVPNCore
@testable import PowerVPNProduct

func m2ObservedNetworkBaseline(
  generation: VendorHelperGenerationSnapshot
) -> ProductM2NetworkBaseline {
  let fingerprint = NetworkCleanupFingerprint.observed(
    count: 0,
    sha256: String(repeating: "a", count: 64)
  )
  let snapshot = NetworkCleanupSnapshot(
    defaultRoute: fingerprint,
    dns: fingerprint,
    interfaces: NetworkCleanupInterfaceSnapshot(
      inventory: fingerprint,
      utunCount: 0,
      utunTokens: []
    ),
    ipv4Routes: NetworkCleanupRouteSnapshot(
      structural: fingerprint,
      persistent: fingerprint,
      selectedRouteMatchCount: 0,
      selectedRouteTokens: []
    ),
    ipv6Routes: NetworkCleanupRouteSnapshot(
      structural: fingerprint,
      persistent: fingerprint,
      selectedRouteMatchCount: 0,
      selectedRouteTokens: []
    ),
    surge: NetworkCleanupSurgeSnapshot(
      fingerprint: fingerprint,
      mainProcessCount: 0,
      extensionProcessCount: 0,
      helperProcessCount: 0
    ),
    vendorProcesses: NetworkCleanupVendorProcessSnapshot(
      fingerprint: fingerprint,
      officialGUIProcessCount: 0,
      charonProcessCount: 0,
      ipsecProcessCount: 0,
      shellProcessCount: 0,
      identityTokens: []
    ),
    helperGeneration: generation,
    helperObservationState: .observed
  )
  return ProductM2NetworkBaseline(snapshot: snapshot)
}

func m2SSHEvidence(
  _ outcome: ProductM2SSHProofOutcome,
  target: ProductM2SSHTarget = .thu21
) -> ProductM2FreshSSHProofEvidence {
  let proven = outcome == .proven
  return ProductM2FreshSSHProofEvidence(
    target: target,
    outcome: outcome,
    processStarted: proven,
    processReaped: proven,
    exitStatusZero: proven,
    challengeMatched: proven,
    standardOutputWithinLimit: proven,
    standardErrorWithinLimit: proven,
    timedOut: outcome == .timedOut,
    cancelled: outcome == .cancelled
  )
}

let m2ConnectedStatus = ProductM2VendorStatusEvidence(
  outcome: .connected,
  statusEventCount: 1,
  latestClassification: .connected,
  terminalControlOutcome: nil
)

let m2ProvenActiveNetwork = ProductM2ActiveNetworkEvidence(
  complete: true,
  helperSingleRunningGeneration: true,
  surgeStable: true,
  vendorGUIAbsent: true,
  unrelatedVendorHelpersAbsent: true,
  selectedRouteBindingDeltaCount: 1,
  effectiveSelectedRouteBindingIntroduced: true,
  newUtunCount: 1,
  defaultRouteChanged: false,
  dnsChanged: false,
  persistentRoutesChanged: true,
  selectedResourcePathProven: true
)

let m2CompleteCleanup = ProductM2CleanupEvidence(
  defaultRouteRestored: true,
  dnsRestored: true,
  interfacesRestored: true,
  utunRestored: true,
  surgeStateRestored: true,
  helperGenerationRestored: true
)

func m2Receipt(
  _ outcome: ProductM2ControlOutcome,
  requestSent: Bool,
  statusEventCount: Int = 0,
  statusAtSubmission: ProductM2VendorStatusClassification? = nil
) -> ProductM2ControlReceipt {
  ProductM2ControlReceipt(
    outcome: outcome,
    requestSent: requestSent,
    transportAcknowledged: outcome == .transportAcknowledged,
    peerGenerationValidated: outcome == .transportAcknowledged,
    statusEventCount: statusEventCount,
    statusAtSubmission: statusAtSubmission
  )
}
