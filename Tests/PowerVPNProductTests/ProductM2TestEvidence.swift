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

/// Observed vendor-process inventory for capture-classification fixtures.
/// All-zero counts are consistent with an inactive helper generation; a
/// non-zero `ipsecProcessCount` or a charon count below the generation's
/// active count reproduces the structural active-state inconsistency.
func m2VendorProcessesFixture(
  ipsecProcessCount: Int = 0,
  charonProcessCount: Int = 0
) -> NetworkCleanupVendorProcessSnapshot {
  let itemCount = ipsecProcessCount + charonProcessCount
  return NetworkCleanupVendorProcessSnapshot(
    fingerprint: .observed(
      count: itemCount,
      sha256: String(repeating: "a", count: 64)
    ),
    officialGUIProcessCount: 0,
    charonProcessCount: charonProcessCount,
    ipsecProcessCount: ipsecProcessCount,
    shellProcessCount: 0,
    identityTokens: Set((0..<itemCount).map { Data([UInt8($0 + 1)]) })
  )
}

/// Snapshot fixture for `ProductM2ActiveCaptureOutcome` mapping tests. The
/// default shape (inactive helper, consistent zero-count vendor processes) is
/// complete; each parameter bends exactly one completeness axis.
func m2CaptureSnapshotFixture(
  helperGeneration: VendorHelperGenerationSnapshot = m2ColdGeneration,
  helperObservationState: NetworkCleanupObservationState = .observed,
  vendorProcesses: NetworkCleanupVendorProcessSnapshot = m2VendorProcessesFixture(),
  effectiveSelectedRoute: NetworkCleanupEffectiveRouteSnapshot? = nil,
  defaultRoute: NetworkCleanupFingerprint = .observed(
    count: 0,
    sha256: String(repeating: "a", count: 64)
  )
) -> NetworkCleanupSnapshot {
  let fingerprint = NetworkCleanupFingerprint.observed(
    count: 0,
    sha256: String(repeating: "a", count: 64)
  )
  return NetworkCleanupSnapshot(
    defaultRoute: defaultRoute,
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
      selectedRouteTokens: [],
      effectiveSelectedRoute: effectiveSelectedRoute
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
    vendorProcesses: vendorProcesses,
    helperGeneration: helperGeneration,
    helperObservationState: helperObservationState
  )
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
    cancelled: outcome == .cancelled,
    failureClass: outcome == .rejected ? .unclassified : nil
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

func m2CleanupEvidence(
  complete: Bool = true,
  defaultRouteRestored: Bool = true,
  dnsRestored: Bool = true,
  interfacesRestored: Bool = true,
  utunRestored: Bool = true,
  persistentRoutesRestored: Bool = true,
  selectedRouteResidueCount: Int = 0,
  surgeStateRestored: Bool = true,
  vendorProcessesRestored: Bool = true,
  helperGenerationRestored: Bool = true,
  structuralRouteTablesEqual: Bool = true
) -> ProductM2CleanupEvidence {
  ProductM2CleanupEvidence(
    complete: complete,
    defaultRouteRestored: defaultRouteRestored,
    dnsRestored: dnsRestored,
    interfacesRestored: interfacesRestored,
    utunRestored: utunRestored,
    persistentRoutesRestored: persistentRoutesRestored,
    selectedRouteResidueCount: selectedRouteResidueCount,
    surgeStateRestored: surgeStateRestored,
    vendorProcessesRestored: vendorProcessesRestored,
    helperGenerationRestored: helperGenerationRestored,
    structuralRouteTablesEqual: structuralRouteTablesEqual
  )
}

let m2CompleteCleanup = m2CleanupEvidence()

let m2SingleDimensionCleanupFailures: [ProductM2CleanupEvidence] = [
  m2CleanupEvidence(complete: false),
  m2CleanupEvidence(defaultRouteRestored: false),
  m2CleanupEvidence(dnsRestored: false),
  m2CleanupEvidence(interfacesRestored: false),
  m2CleanupEvidence(utunRestored: false),
  m2CleanupEvidence(persistentRoutesRestored: false),
  m2CleanupEvidence(selectedRouteResidueCount: 1),
  m2CleanupEvidence(surgeStateRestored: false),
  m2CleanupEvidence(vendorProcessesRestored: false),
  m2CleanupEvidence(helperGenerationRestored: false),
  m2CleanupEvidence(structuralRouteTablesEqual: false),
]

func m2Receipt(
  _ outcome: ProductM2ControlOutcome,
  requestSent: Bool,
  statusEventCount: Int = 0,
  statusAtSubmission: ProductM2VendorStatusClassification? = nil,
  startEventSignatures: [String]? = nil,
  startReplySignatures: [String]? = nil,
  unexpectedEventSignature: [String]? = nil,
  completionSource: ProductM2ControlCompletionSource = .submission
) -> ProductM2ControlReceipt {
  ProductM2ControlReceipt(
    outcome: outcome,
    requestSent: requestSent,
    transportAcknowledged: outcome == .transportAcknowledged,
    peerGenerationValidated: outcome == .transportAcknowledged,
    completionSource: completionSource,
    statusEventCount: statusEventCount,
    statusAtSubmission: statusAtSubmission,
    startEventSignatures: startEventSignatures,
    startReplySignatures: startReplySignatures,
    unexpectedEventSignature: unexpectedEventSignature
  )
}
