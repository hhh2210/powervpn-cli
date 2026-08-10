package struct ProductM2ProvisionalStopCapability: Sendable {
  private let stopOperation: @Sendable () async -> ProductM2ControlReceipt

  init(
    stopOperation: @escaping @Sendable () async -> ProductM2ControlReceipt
  ) {
    self.stopOperation = stopOperation
  }

  package func stop() async -> ProductM2ControlReceipt {
    await stopOperation()
  }
}
