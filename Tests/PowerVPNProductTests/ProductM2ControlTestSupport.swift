import PowerVPNCore

@testable import PowerVPNProduct

struct ProductM2TestControlPlan: Sendable {
  let startOutcome: ProductM2ControlOutcome
  let startRequestSent: Bool
  let retainLease: Bool
  let generationAfterBegin: VendorHelperGenerationSnapshot
  let statusEvidence: ProductM2VendorStatusEvidence
  let stopStatusAtSubmission: ProductM2VendorStatusClassification?
  let stopOutcome: ProductM2ControlOutcome
  let stopRequestSent: Bool

  static let acknowledged = Self(
    startOutcome: .transportAcknowledged,
    startRequestSent: true,
    retainLease: true,
    generationAfterBegin: m2RunningGeneration,
    statusEvidence: m2ConnectedStatus,
    stopStatusAtSubmission: .connected,
    stopOutcome: .transportAcknowledged,
    stopRequestSent: true
  )

  static func acknowledged(
    status: ProductM2VendorStatusEvidence
  ) -> Self {
    Self(
      startOutcome: .transportAcknowledged,
      startRequestSent: true,
      retainLease: true,
      generationAfterBegin: m2RunningGeneration,
      statusEvidence: status,
      stopStatusAtSubmission: status.latestClassification,
      stopOutcome: .transportAcknowledged,
      stopRequestSent: true
    )
  }

  static func acknowledged(
    stopStatus: ProductM2VendorStatusClassification?
  ) -> Self {
    Self(
      startOutcome: .transportAcknowledged,
      startRequestSent: true,
      retainLease: true,
      generationAfterBegin: m2RunningGeneration,
      statusEvidence: m2ConnectedStatus,
      stopStatusAtSubmission: stopStatus,
      stopOutcome: .transportAcknowledged,
      stopRequestSent: true
    )
  }

  static func noLease(
    generation: VendorHelperGenerationSnapshot
  ) -> Self {
    Self(
      startOutcome: .timeout,
      startRequestSent: true,
      retainLease: false,
      generationAfterBegin: generation,
      statusEvidence: .notAttempted,
      stopStatusAtSubmission: nil,
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
      statusEvidence: m2ConnectedStatus,
      stopStatusAtSubmission: requestSent ? .connected : nil,
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
      return ProductM2PendingStart {
        trace.record("await_start")
        let validatorAccepted =
          plan.startOutcome == .transportAcknowledged
          ? await validator() : false
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
          ? ProductM2ControlLease(
            stopOperation: {
              trace.record("stop")
              return m2Receipt(
                plan.stopOutcome,
                requestSent: plan.stopRequestSent,
                statusEventCount: plan.statusEvidence.statusEventCount,
                statusAtSubmission: plan.stopStatusAtSubmission
              )
            },
            statusOperation: {
              trace.record("status_wait")
              return plan.statusEvidence
            }
          ) : nil
        return ProductM2StartResult(receipt: receipt, lease: lease)
      }
    },
    emergencyStop: { predicate, validator in
      trace.record("emergency_stop")
      guard await predicate() else { return .unsent(.preflightBlocked) }
      let accepted = await validator()
      return m2Receipt(
        accepted ? .transportAcknowledged : .peerGenerationMismatch,
        requestSent: accepted
      )
    }
  )
}
