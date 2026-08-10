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
