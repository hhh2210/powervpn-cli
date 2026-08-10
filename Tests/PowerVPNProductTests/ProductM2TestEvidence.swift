@testable import PowerVPNProduct

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
