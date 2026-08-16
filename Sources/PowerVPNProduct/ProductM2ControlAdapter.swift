import Foundation
import PowerVPNCore

package struct ProductM2ControlReceipt: Equatable, Sendable {
  package let outcome: ProductM2ControlOutcome
  package let requestSent: Bool
  package let transportAcknowledged: Bool
  package let peerGenerationValidated: Bool
  package let replyUnavailableObserved: Bool
  package let completionSource: ProductM2ControlCompletionSource
  package let statusEventCount: Int
  package let statusAtSubmission: ProductM2VendorStatusClassification?
  package let startEventSignatures: [String]?
  package let startReplySignatures: [String]?
  package let unexpectedEventSignature: [String]?

  init(_ receipt: VendorCharonControlReceipt) {
    outcome = ProductM2ControlOutcome(receipt.outcome)
    requestSent = receipt.requestSent
    transportAcknowledged = receipt.transportAcknowledged
    peerGenerationValidated = receipt.peerGenerationValidated
    replyUnavailableObserved = receipt.replyUnavailableObserved
    completionSource = ProductM2ControlCompletionSource(receipt.completionSource)
    statusEventCount = receipt.statusEventCount
    statusAtSubmission = receipt.statusAtSubmission.map(
      ProductM2VendorStatusClassification.init)
    if receipt.operation == .startConnection {
      startEventSignatures =
        receipt.incomingEventSignatures.isEmpty ? nil : receipt.incomingEventSignatures
      startReplySignatures =
        receipt.replySignatures.isEmpty ? nil : receipt.replySignatures
      unexpectedEventSignature = receipt.unexpectedEventSignature
    } else {
      startEventSignatures = nil
      startReplySignatures = nil
      unexpectedEventSignature = nil
    }
  }

  init(
    outcome: ProductM2ControlOutcome,
    requestSent: Bool,
    transportAcknowledged: Bool,
    peerGenerationValidated: Bool,
    replyUnavailableObserved: Bool = false,
    completionSource: ProductM2ControlCompletionSource = .submission,
    statusEventCount: Int = 0,
    statusAtSubmission: ProductM2VendorStatusClassification? = nil,
    startEventSignatures: [String]? = nil,
    startReplySignatures: [String]? = nil,
    unexpectedEventSignature: [String]? = nil
  ) {
    self.outcome = outcome
    self.requestSent = requestSent
    self.transportAcknowledged = transportAcknowledged
    self.peerGenerationValidated = peerGenerationValidated
    self.replyUnavailableObserved = replyUnavailableObserved
    self.completionSource = completionSource
    self.statusEventCount = statusEventCount
    self.statusAtSubmission = statusAtSubmission
    self.startEventSignatures = startEventSignatures
    self.startReplySignatures = startReplySignatures
    self.unexpectedEventSignature = unexpectedEventSignature
  }

  package static func unsent(
    _ outcome: ProductM2ControlOutcome
  ) -> Self {
    Self(
      outcome: outcome,
      requestSent: false,
      transportAcknowledged: false,
      peerGenerationValidated: false,
      statusEventCount: 0,
      statusAtSubmission: nil
    )
  }
}

extension ProductM2ControlCompletionSource {
  fileprivate init(_ source: VendorCharonControlCompletionSource) {
    switch source {
    case .submission: self = .submission
    case .ordinaryConnection: self = .ordinaryConnection
    case .replyDictionary: self = .replyDictionary
    case .replyUnavailableThenOrdinary: self = .replyUnavailableThenOrdinary
    case .connectionTerminal: self = .connectionTerminal
    case .timeout: self = .timeout
    case .callerCancel: self = .callerCancel
    }
  }
}

package struct ProductM2ControlLease: Sendable {
  private let stopOperation: @Sendable (Int) async -> ProductM2ControlReceipt
  private let statusOperation: @Sendable (Int) async -> ProductM2VendorStatusEvidence
  private let statusEventCountOperation: @Sendable () -> Int
  private let routeToggleOperation:
    @Sendable (Bool, Int, @escaping @Sendable () async -> Bool) async
      -> ProductM2ControlReceipt

  init(
    stopOperation: @escaping @Sendable (Int) async -> ProductM2ControlReceipt,
    statusOperation: @escaping @Sendable (Int) async -> ProductM2VendorStatusEvidence,
    statusEventCountOperation: @escaping @Sendable () -> Int = { 0 },
    routeToggleOperation:
      @escaping @Sendable (
        Bool,
        Int,
        @escaping @Sendable () async -> Bool
      ) async -> ProductM2ControlReceipt
  ) {
    self.stopOperation = stopOperation
    self.statusOperation = statusOperation
    self.statusEventCountOperation = statusEventCountOperation
    self.routeToggleOperation = routeToggleOperation
  }

  package func stop(timeoutMilliseconds: Int) async -> ProductM2ControlReceipt {
    await stopOperation(timeoutMilliseconds)
  }

  package func waitForConnectedStatus(
    timeoutMilliseconds: Int
  ) async -> ProductM2VendorStatusEvidence {
    await statusOperation(timeoutMilliseconds)
  }

  package var statusEventCount: Int {
    statusEventCountOperation()
  }

  package func setSelectedNCEnabled(
    _ enabled: Bool,
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> ProductM2ControlReceipt {
    await routeToggleOperation(enabled, timeoutMilliseconds, peerGenerationValidator)
  }
}

package struct ProductM2StartResult: Sendable {
  package let receipt: ProductM2ControlReceipt
  package let lease: ProductM2ControlLease?
  package let provisionalStopCapability: ProductM2ProvisionalStopCapability?
  package let emergencyStopCapability: ProductM2EmergencyStopCapability?

  init(
    receipt: ProductM2ControlReceipt,
    lease: ProductM2ControlLease?,
    provisionalStopCapability: ProductM2ProvisionalStopCapability? = nil,
    emergencyStopCapability: ProductM2EmergencyStopCapability? = nil
  ) {
    self.receipt = receipt
    self.lease = lease
    self.provisionalStopCapability = provisionalStopCapability
    self.emergencyStopCapability = emergencyStopCapability
  }
}

package struct ProductM2PendingStart: Sendable {
  private let operation: @Sendable () async -> ProductM2StartResult

  init(operation: @escaping @Sendable () async -> ProductM2StartResult) {
    self.operation = operation
  }

  package func result() async -> ProductM2StartResult { await operation() }
}

package struct ProductM2ControlAdapter: Sendable {
  private let beginOperation:
    @Sendable (
      VendorCharonStartSnapshot,
      Int,
      @escaping @Sendable () async -> Bool,
      @escaping @Sendable () throws -> Void
    ) throws -> ProductM2PendingStart

  package init(transport: RawVendorCharonControlTransport) {
    beginOperation = { snapshot, timeoutMilliseconds, validator, commit in
      let pending = try transport.beginStart(
        snapshot: snapshot,
        timeoutMilliseconds: timeoutMilliseconds,
        peerGenerationValidator: validator,
        commitStartAuthorization: commit
      )
      return ProductM2PendingStart {
        let result = await pending.result()
        return ProductM2StartResult(
          receipt: ProductM2ControlReceipt(result.receipt),
          lease: result.lease.map { lease in
            ProductM2ControlLease(
              stopOperation: { timeoutMilliseconds in
                ProductM2ControlReceipt(
                  await lease.stop(
                    timeoutMilliseconds: timeoutMilliseconds
                  ))
              },
              statusOperation: { timeoutMilliseconds in
                ProductM2VendorStatusEvidence(
                  await lease.waitForConnectedStatus(
                    timeoutMilliseconds: timeoutMilliseconds
                  ))
              },
              statusEventCountOperation: {
                lease.observation.statusEventCount
              },
              routeToggleOperation: { enabled, timeoutMilliseconds, validator in
                ProductM2ControlReceipt(
                  await lease.setSelectedNCEnabled(
                    enabled,
                    timeoutMilliseconds: timeoutMilliseconds,
                    peerGenerationValidator: validator
                  ))
              }
            )
          },
          provisionalStopCapability: result.provisionalStopCapability.map { capability in
            ProductM2ProvisionalStopCapability { timeoutMilliseconds in
              ProductM2ControlReceipt(
                await capability.stop(
                  timeoutMilliseconds: timeoutMilliseconds
                ))
            }
          },
          emergencyStopCapability: result.stopContext.map { stopContext in
            ProductM2EmergencyStopCapability {
              timeoutMilliseconds,
              expectedRunningPredicate,
              peerGenerationValidator in
              ProductM2ControlReceipt(
                await transport.emergencyStop(
                  timeoutMilliseconds: timeoutMilliseconds,
                  stopContext: stopContext,
                  expectedRunningPredicate: expectedRunningPredicate,
                  peerGenerationValidator: peerGenerationValidator
                ))
            }
          }
        )
      }
    }
  }

  package init() {
    self.init(transport: RawVendorCharonControlTransport())
  }

  package static func runtimePreflightAccepted() -> Bool {
    VendorXPCSessionContract.runtimePreflight() == .accepted
  }

  init(
    beginStart:
      @escaping @Sendable (
        VendorCharonStartSnapshot,
        Int,
        @escaping @Sendable () async -> Bool
      ) -> ProductM2PendingStart,
    emergencyStop:
      @escaping @Sendable (
        Int,
        @escaping @Sendable () async -> Bool,
        @escaping @Sendable () async -> Bool
      ) async -> ProductM2ControlReceipt
  ) {
    beginOperation = { snapshot, timeoutMilliseconds, validator, commit in
      try commit()
      let pending = beginStart(snapshot, timeoutMilliseconds, validator)
      return ProductM2PendingStart {
        let result = await pending.result()
        guard result.receipt.requestSent else { return result }
        return ProductM2StartResult(
          receipt: result.receipt,
          lease: result.lease,
          provisionalStopCapability: result.provisionalStopCapability,
          emergencyStopCapability: result.emergencyStopCapability
            ?? ProductM2EmergencyStopCapability(stopOperation: emergencyStop)
        )
      }
    }
  }

  package func beginStart(
    snapshot: VendorCharonStartSnapshot,
    timeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable () async -> Bool,
    commitStartAuthorization: @escaping @Sendable () throws -> Void
  ) throws -> ProductM2PendingStart {
    try beginOperation(
      snapshot,
      timeoutMilliseconds,
      peerGenerationValidator,
      commitStartAuthorization
    )
  }

}

package enum ProductM2GenerationFence {
  package static func sameColdGeneration(
    _ before: VendorHelperGenerationSnapshot,
    _ current: VendorHelperGenerationSnapshot
  ) -> Bool {
    before.exactInactive && current.exactInactive && before.runs == current.runs
  }

  package static func singleRunningGeneration(
    _ before: VendorHelperGenerationSnapshot,
    _ current: VendorHelperGenerationSnapshot
  ) -> Bool {
    guard before.exactInactive, current.exactRunning,
      let runs = before.runs, runs < Int.max
    else { return false }
    return current.runs == runs + 1
  }

  package static func singleExitedGeneration(
    _ before: VendorHelperGenerationSnapshot,
    _ current: VendorHelperGenerationSnapshot
  ) -> Bool {
    guard before.exactInactive, current.exactInactive,
      let runs = before.runs, runs < Int.max
    else { return false }
    return current.runs == runs + 1
  }

  package static func validatesReply(
    before: VendorHelperGenerationSnapshot,
    current: VendorHelperGenerationSnapshot
  ) -> Bool {
    VendorCharonSessionGenerationValidator.validate(
      before: before,
      current: current
    )
  }
}

extension ProductM2ControlOutcome {
  package init(_ outcome: VendorCharonControlOutcome) {
    switch outcome {
    case .transportAcknowledged: self = .transportAcknowledged
    case .preflightBlocked: self = .preflightBlocked
    case .helperVersionMismatch: self = .helperVersionMismatch
    case .helperVersionRejected: self = .helperVersionRejected
    case .invalidTimeout: self = .invalidTimeout
    case .cancelled: self = .cancelled
    case .timeout: self = .timeout
    case .snapshotEncodingFailed: self = .snapshotEncodingFailed
    case .peerGenerationMismatch: self = .peerGenerationMismatch
    case .connectionInterrupted: self = .connectionInterrupted
    case .connectionInvalid: self = .connectionInvalid
    case .peerCodeSigningRequirement: self = .peerCodeSigningRequirement
    case .unexpectedXPCError: self = .unexpectedXPCError
    case .unexpectedConnectionEvent: self = .unexpectedConnectionEvent
    case .unexpectedReplyPayload: self = .unexpectedReplyPayload
    case .helperRejected: self = .helperRejected
    case .leaseClosed: self = .leaseClosed
    }
  }
}
