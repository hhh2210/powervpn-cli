import Foundation
import PowerVPNCore

package struct ProductM2ControlReceipt: Equatable, Sendable {
  package let outcome: ProductM2ControlOutcome
  package let requestSent: Bool
  package let transportAcknowledged: Bool
  package let peerGenerationValidated: Bool
  package let statusEventCount: Int
  package let statusAtSubmission: ProductM2VendorStatusClassification?

  init(_ receipt: VendorCharonControlReceipt) {
    outcome = ProductM2ControlOutcome(receipt.outcome)
    requestSent = receipt.requestSent
    transportAcknowledged = receipt.transportAcknowledged
    peerGenerationValidated = receipt.peerGenerationValidated
    statusEventCount = receipt.statusEventCount
    statusAtSubmission = receipt.statusAtSubmission.map(
      ProductM2VendorStatusClassification.init)
  }

  init(
    outcome: ProductM2ControlOutcome,
    requestSent: Bool,
    transportAcknowledged: Bool,
    peerGenerationValidated: Bool,
    statusEventCount: Int = 0,
    statusAtSubmission: ProductM2VendorStatusClassification? = nil
  ) {
    self.outcome = outcome
    self.requestSent = requestSent
    self.transportAcknowledged = transportAcknowledged
    self.peerGenerationValidated = peerGenerationValidated
    self.statusEventCount = statusEventCount
    self.statusAtSubmission = statusAtSubmission
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

package struct ProductM2ControlLease: Sendable {
  private let stopOperation: @Sendable () async -> ProductM2ControlReceipt
  private let statusOperation: @Sendable () async -> ProductM2VendorStatusEvidence

  init(
    stopOperation: @escaping @Sendable () async -> ProductM2ControlReceipt,
    statusOperation: @escaping @Sendable () async -> ProductM2VendorStatusEvidence
  ) {
    self.stopOperation = stopOperation
    self.statusOperation = statusOperation
  }

  package func stop() async -> ProductM2ControlReceipt {
    await stopOperation()
  }

  package func waitForConnectedStatus() async -> ProductM2VendorStatusEvidence {
    await statusOperation()
  }
}

package struct ProductM2StartResult: Sendable {
  package let receipt: ProductM2ControlReceipt
  package let lease: ProductM2ControlLease?
  package let provisionalStopCapability: ProductM2ProvisionalStopCapability?

  init(
    receipt: ProductM2ControlReceipt,
    lease: ProductM2ControlLease?,
    provisionalStopCapability: ProductM2ProvisionalStopCapability? = nil
  ) {
    self.receipt = receipt
    self.lease = lease
    self.provisionalStopCapability = provisionalStopCapability
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
      @escaping @Sendable () async -> Bool
    ) -> ProductM2PendingStart
  private let emergencyOperation:
    @Sendable (
      @escaping @Sendable () async -> Bool,
      @escaping @Sendable () async -> Bool
    ) async -> ProductM2ControlReceipt

  package init(transport: RawVendorCharonControlTransport) {
    beginOperation = { snapshot, validator in
      let pending = transport.beginStart(
        snapshot: snapshot,
        peerGenerationValidator: validator
      )
      return ProductM2PendingStart {
        let result = await pending.result()
        return ProductM2StartResult(
          receipt: ProductM2ControlReceipt(result.receipt),
          lease: result.lease.map { lease in
            ProductM2ControlLease(
              stopOperation: {
                ProductM2ControlReceipt(
                  await lease.stop(
                    timeoutMilliseconds: RawVendorCharonControlTransport
                      .defaultTimeoutMilliseconds
                  ))
              },
              statusOperation: {
                ProductM2VendorStatusEvidence(
                  await lease.waitForConnectedStatus(
                    timeoutMilliseconds: RawVendorCharonControlTransport
                      .defaultTimeoutMilliseconds
                  ))
              }
            )
          },
          provisionalStopCapability: result.provisionalStopCapability.map { capability in
            ProductM2ProvisionalStopCapability {
              ProductM2ControlReceipt(
                await capability.stop(
                  timeoutMilliseconds: RawVendorCharonControlTransport
                    .defaultTimeoutMilliseconds
                ))
            }
          }
        )
      }
    }
    emergencyOperation = { predicate, validator in
      ProductM2ControlReceipt(
        await transport.emergencyStop(
          timeoutMilliseconds: RawVendorCharonControlTransport
            .defaultTimeoutMilliseconds,
          expectedRunningPredicate: predicate,
          peerGenerationValidator: validator
        ))
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
        @escaping @Sendable () async -> Bool
      ) -> ProductM2PendingStart,
    emergencyStop:
      @escaping @Sendable (
        @escaping @Sendable () async -> Bool,
        @escaping @Sendable () async -> Bool
      ) async -> ProductM2ControlReceipt
  ) {
    beginOperation = beginStart
    emergencyOperation = emergencyStop
  }

  package func beginStart(
    snapshot: VendorCharonStartSnapshot,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) -> ProductM2PendingStart {
    beginOperation(snapshot, peerGenerationValidator)
  }

  package func emergencyStop(
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> ProductM2ControlReceipt {
    await emergencyOperation(expectedRunningPredicate, peerGenerationValidator)
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
    case .leaseClosed: self = .leaseClosed
    }
  }
}
