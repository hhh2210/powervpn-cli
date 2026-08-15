package struct ProductM2ProvisionalStopCapability: Sendable {
  private let stopOperation: @Sendable (Int) async -> ProductM2ControlReceipt

  init(
    stopOperation: @escaping @Sendable (Int) async -> ProductM2ControlReceipt
  ) {
    self.stopOperation = stopOperation
  }

  package func stop(timeoutMilliseconds: Int) async -> ProductM2ControlReceipt {
    await stopOperation(timeoutMilliseconds)
  }
}

package struct ProductM2EmergencyStopCapability: Sendable {
  private let stopOperation:
    @Sendable (
      Int,
      @escaping @Sendable () async -> Bool,
      @escaping @Sendable () async -> Bool
    ) async -> ProductM2ControlReceipt

  init(
    stopOperation:
      @escaping @Sendable (
        Int,
        @escaping @Sendable () async -> Bool,
        @escaping @Sendable () async -> Bool
      ) async -> ProductM2ControlReceipt
  ) {
    self.stopOperation = stopOperation
  }

  package func stop(
    timeoutMilliseconds: Int,
    expectedRunningPredicate: @escaping @Sendable () async -> Bool,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async -> ProductM2ControlReceipt {
    await stopOperation(
      timeoutMilliseconds,
      expectedRunningPredicate,
      peerGenerationValidator
    )
  }
}
