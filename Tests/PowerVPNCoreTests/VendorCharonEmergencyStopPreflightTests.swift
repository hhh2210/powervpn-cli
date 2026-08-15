import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonEmergencyStopPreflightTests {
  @Test func invalidAndPreCancelledCallsDoNotEvaluateGateOrCreateDriver() async {
    let invalidFactory = EmergencyConnectionDriverFactory()
    let gate = EmergencyStopGate(factory: invalidFactory, result: true)
    let invalid = await emergencyTransport(invalidFactory).emergencyStop(
      timeoutMilliseconds: 0,
      stopContext: syntheticEmergencyStopContext,
      expectedRunningPredicate: gate.evaluate,
      peerGenerationValidator: { true }
    )
    #expect(invalid.outcome == .invalidTimeout)
    #expect(gate.callCount == 0)
    #expect(invalidFactory.callCount == 0)

    let cancelledFactory = EmergencyConnectionDriverFactory()
    let cancelled = await Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return await emergencyTransport(cancelledFactory).emergencyStop(
        timeoutMilliseconds: 500,
        stopContext: syntheticEmergencyStopContext,
        expectedRunningPredicate: { true },
        peerGenerationValidator: { true }
      )
    }.value
    #expect(cancelled.outcome == .cancelled)
    #expect(cancelledFactory.callCount == 0)
  }

  @Test func fixedProductionSurfaceHasNoServiceOrArbitraryStopPayloadInput() {
    _ = RawVendorCharonControlTransport()
    #expect(
      SystemVendorCharonEmergencyConnectionDriver.serviceName == "com.leadsec.charon-xpc"
    )
    #expect(
      VendorXPCGetVersionRequestContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "get_version"),
      ])
    #expect(
      VendorCharonStopContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "stop_connection"),
      ])
  }
}
