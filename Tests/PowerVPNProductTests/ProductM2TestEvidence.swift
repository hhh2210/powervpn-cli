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
  requestSent: Bool
) -> ProductM2ControlReceipt {
  ProductM2ControlReceipt(
    outcome: outcome,
    requestSent: requestSent,
    transportAcknowledged: outcome == .transportAcknowledged,
    peerGenerationValidated: outcome == .transportAcknowledged
  )
}
