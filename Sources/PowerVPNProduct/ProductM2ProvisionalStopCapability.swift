package struct ProductM2ProvisionalStopCapability: Sendable {
  private let stopOperation: @Sendable (Int) async -> ProductM2ControlReceipt
  private let awaitPostStopDrainOperation: @Sendable () async -> Void

  init(
    stopOperation: @escaping @Sendable (Int) async -> ProductM2ControlReceipt,
    awaitPostStopDrainOperation: @escaping @Sendable () async -> Void = {}
  ) {
    self.stopOperation = stopOperation
    self.awaitPostStopDrainOperation = awaitPostStopDrainOperation
  }

  package func stop(timeoutMilliseconds: Int) async -> ProductM2ControlReceipt {
    await stopOperation(timeoutMilliseconds)
  }

  package func awaitPostStopDrain() async {
    await awaitPostStopDrainOperation()
  }
}

struct ProductM2EmergencyStopAttempt: Sendable {
  let receipt: ProductM2ControlReceipt
  let awaitPostStopDrain: @Sendable () async -> Void
}

package struct ProductM2EmergencyStopCapability: Sendable {
  private let stopOperation:
    @Sendable (
      Int,
      @escaping @Sendable () async -> Bool,
      @escaping @Sendable () async -> Bool
    ) async -> ProductM2EmergencyStopAttempt

  init(
    stopOperation:
      @escaping @Sendable (
        Int,
        @escaping @Sendable () async -> Bool,
        @escaping @Sendable () async -> Bool
      ) async -> ProductM2ControlReceipt
  ) {
    self.stopOperation = { timeout, predicate, validator in
      ProductM2EmergencyStopAttempt(
        receipt: await stopOperation(timeout, predicate, validator),
        awaitPostStopDrain: {}
      )
    }
  }

  init(
    drainingStopOperation:
      @escaping @Sendable (
        Int,
        @escaping @Sendable () async -> Bool,
        @escaping @Sendable () async -> Bool
      ) async -> (ProductM2ControlReceipt, @Sendable () async -> Void)
  ) {
    stopOperation = { timeout, predicate, validator in
      let (receipt, awaitPostStopDrain) = await drainingStopOperation(
        timeout,
        predicate,
        validator
      )
      return ProductM2EmergencyStopAttempt(
        receipt: receipt,
        awaitPostStopDrain: awaitPostStopDrain
      )
    }
  }

  package func stop(
    timeoutMilliseconds: Int,
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> ProductM2ControlReceipt {
    (await stopAttempt(
      timeoutMilliseconds: timeoutMilliseconds,
      expectedRunningPredicate: expectedRunningPredicate,
      peerGenerationValidator: peerGenerationValidator
    )).receipt
  }

  func stopAttempt(
    timeoutMilliseconds: Int,
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> ProductM2EmergencyStopAttempt {
    await stopOperation(
      timeoutMilliseconds,
      expectedRunningPredicate,
      peerGenerationValidator
    )
  }
}
