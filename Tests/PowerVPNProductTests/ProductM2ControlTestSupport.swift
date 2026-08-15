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
      stopOutcome: .connectionInvalid,
      stopRequestSent: false
    )
  }

  static func submittedFailure(
    _ outcome: ProductM2ControlOutcome,
    generation: VendorHelperGenerationSnapshot = m2RunningGeneration,
    stopOutcome: ProductM2ControlOutcome = .transportAcknowledged,
    stopRequestSent: Bool = true
  ) -> Self {
    Self(
      startOutcome: outcome,
      startRequestSent: true,
      retainLease: false,
      generationAfterBegin: generation,
      statusEvidence: .notAttempted,
      stopStatusAtSubmission: nil,
      stopOutcome: stopOutcome,
      stopRequestSent: stopRequestSent
    )
  }

  static let preSubmissionFailure = Self(
    startOutcome: .connectionInvalid,
    startRequestSent: false,
    retainLease: false,
    generationAfterBegin: m2ColdGeneration,
    statusEvidence: .notAttempted,
    stopStatusAtSubmission: nil,
    stopOutcome: .notAttempted,
    stopRequestSent: false
  )

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
  plan: ProductM2TestControlPlan,
  startEventSignatures: [String]? = nil,
  startReplySignatures: [String]? = nil,
  unexpectedEventSignature: [String]? = nil,
  onBeginStart: @escaping @Sendable (Int) -> Void = { _ in },
  onAwaitStart: @escaping @Sendable () -> Void = {},
  onStop: @escaping @Sendable (Int) -> Void = { _ in },
  onEmergencyStop: @escaping @Sendable (Int) -> Void = { _ in }
) -> ProductM2ControlAdapter {
  ProductM2ControlAdapter(
    beginStart: { _, timeoutMilliseconds, validator in
      trace.record("begin_start")
      onBeginStart(timeoutMilliseconds)
      trace.setGeneration(plan.generationAfterBegin)
      return ProductM2PendingStart {
        trace.record("await_start")
        onAwaitStart()
        if plan.startOutcome == .cancelled { withUnsafeCurrentTask { $0?.cancel() } }
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
          requestSent: plan.startRequestSent,
          startEventSignatures: startEventSignatures,
          startReplySignatures: startReplySignatures,
          unexpectedEventSignature: unexpectedEventSignature
        )
        let stopOperation: @Sendable (Int) async -> ProductM2ControlReceipt = { timeout in
          trace.record("stop")
          onStop(timeout)
          if Task.isCancelled { return .unsent(.cancelled) }
          return m2Receipt(
            plan.stopOutcome,
            requestSent: plan.stopRequestSent,
            statusEventCount: plan.statusEvidence.statusEventCount,
            statusAtSubmission: plan.stopStatusAtSubmission
          )
        }
        let lease: ProductM2ControlLease? =
          acknowledged && plan.retainLease
          ? ProductM2ControlLease(
            stopOperation: stopOperation,
            statusOperation: { _ in
              trace.record("status_wait")
              return plan.statusEvidence
            }
          ) : nil
        let provisionalStopCapability =
          !acknowledged && receipt.requestSent
          ? ProductM2ProvisionalStopCapability(stopOperation: stopOperation)
          : nil
        return ProductM2StartResult(
          receipt: receipt,
          lease: lease,
          provisionalStopCapability: provisionalStopCapability
        )
      }
    },
    emergencyStop: { timeout, predicate, validator in
      trace.record("emergency_stop")
      guard await predicate() else { return .unsent(.preflightBlocked) }
      let accepted = await validator()
      let receipt = m2Receipt(
        accepted ? .transportAcknowledged : .peerGenerationMismatch,
        requestSent: accepted
      )
      onEmergencyStop(timeout)
      return receipt
    }
  )
}
