import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonEmergencyStopTests {
  @Test func blockedPreflightCreatesNoDriverAndSendsNothing() async {
    let factory = CharonControlDriverFactory()
    let gate = EmergencyStopGate(factory: factory, result: false)

    let receipt = await controlTransport(factory).emergencyStop(
      timeoutMilliseconds: 500,
      expectedRunningPredicate: gate.evaluate,
      peerGenerationValidator: { _ in true }
    )

    #expect(gate.callCount == 1)
    #expect(gate.factoryCallsObserved == [0])
    #expect(receipt.operation == .stopConnection)
    #expect(receipt.outcome == .preflightBlocked)
    #expect(!receipt.requestSent)
    #expect(!receipt.helperMayHaveMutated)
    #expect(!receipt.connectionCancelRequested)
    #expect(factory.callCount == 0)
  }

  @Test func allowedPreflightSendsOnlyExactStopAndAcknowledgesExpectedPeer() async {
    let factory = CharonControlDriverFactory()
    let gate = EmergencyStopGate(factory: factory, result: true)
    let task = Task {
      await controlTransport(factory).emergencyStop(
        timeoutMilliseconds: 500,
        expectedRunningPredicate: gate.evaluate,
        peerGenerationValidator: { $0 == 41 }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    #expect(gate.callCount == 1)
    #expect(gate.factoryCallsObserved == [0])
    #expect(
      factory.driver.observations == [
        ControlEnvelopeObservation(
          operation: "stop_connection",
          exactStartShape: false,
          exactStopShape: true
        )
      ])
    factory.driver.emitConnection(.emptyDispatcherTail)
    factory.driver.emitReply(.emptyAcknowledgement(peerPID: 41), at: 0)
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.helperMayHaveMutated)
    #expect(receipt.connectionCancelRequested)
    #expect(receipt.dispatcherTailEventCount == 1)
    #expect(!receipt.cleanupEstablished)
    #expect(!receipt.helperSuccessEstablished)
    #expect(factory.callCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func stateDriftIsReportedAsPeerGenerationMismatch() async {
    let factory = CharonControlDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { $0 == 7 })
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement(peerPID: 8), at: 0)
    let receipt = await task.value

    #expect(receipt.outcome == .peerGenerationMismatch)
    #expect(receipt.emptyReplyObserved)
    #expect(!receipt.peerGenerationValidated)
    #expect(!receipt.transportAcknowledged)
    #expect(!receipt.cleanupEstablished)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func timeoutCancelsOnceAndIgnoresLateReply() async {
    let factory = CharonControlDriverFactory()
    let receipt = await controlTransport(factory).emergencyStop(
      timeoutMilliseconds: 5,
      expectedRunningPredicate: { true },
      peerGenerationValidator: { _ in true }
    )

    #expect(receipt.outcome == .timeout)
    #expect(receipt.requestSent)
    #expect(receipt.connectionCancelRequested)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitReply(.emptyAcknowledgement(peerPID: 1), at: 0)
    await Task.yield()
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func cancellationAfterSubmitCancelsOnceAndIgnoresLateEvents() async {
    let factory = CharonControlDriverFactory()
    let task = emergencyStopTask(factory)
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(receipt.requestSent)
    #expect(receipt.connectionCancelRequested)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitConnection(.connectionInvalid)
    factory.driver.emitReply(.emptyAcknowledgement(peerPID: 1), at: 0)
    await Task.yield()
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func replyAndConnectionErrorsAreClosed() async {
    let replyCases: [(VendorCharonControlReplyEvent, VendorCharonControlOutcome)] = [
      (.connectionInterrupted, .connectionInterrupted),
      (.connectionInvalid, .connectionInvalid),
      (.peerCodeSigningRequirement, .peerCodeSigningRequirement),
      (.unexpectedXPCError, .unexpectedXPCError),
      (.unexpectedPayload, .unexpectedReplyPayload),
    ]
    for (event, expected) in replyCases {
      let factory = CharonControlDriverFactory()
      let task = emergencyStopTask(factory)
      #expect(await waitForControl { factory.driver.submitCount == 1 })
      factory.driver.emitReply(event, at: 0)
      let receipt = await task.value
      #expect(receipt.outcome == expected)
      #expect(factory.driver.cancelCount == 1)
    }

    let factory = CharonControlDriverFactory()
    let task = emergencyStopTask(factory)
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitConnection(.unexpectedDictionary)
    let receipt = await task.value
    #expect(receipt.outcome == .unexpectedConnectionEvent)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func invalidAndPreCancelledCallsDoNotEvaluateGateOrCreateDriver() async {
    let invalidFactory = CharonControlDriverFactory()
    let gate = EmergencyStopGate(factory: invalidFactory, result: true)
    let invalid = await controlTransport(invalidFactory).emergencyStop(
      timeoutMilliseconds: 0,
      expectedRunningPredicate: gate.evaluate,
      peerGenerationValidator: { _ in true }
    )
    #expect(invalid.outcome == .invalidTimeout)
    #expect(gate.callCount == 0)
    #expect(invalidFactory.callCount == 0)

    let cancelledFactory = CharonControlDriverFactory()
    let cancelled = await Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return await controlTransport(cancelledFactory).emergencyStop(
        timeoutMilliseconds: 500,
        expectedRunningPredicate: { true },
        peerGenerationValidator: { _ in true }
      )
    }.value
    #expect(cancelled.outcome == .cancelled)
    #expect(cancelledFactory.callCount == 0)
  }

  @Test func productionSurfaceHasFixedServiceAndWireContract() {
    _ = RawVendorCharonControlTransport()
    #expect(SystemVendorCharonControlConnectionDriver.serviceName == "com.leadsec.charon-xpc")
    #expect(
      VendorCharonStopContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "stop_connection"),
      ])
  }
}

private func emergencyStopTask(
  _ factory: CharonControlDriverFactory,
  peerGenerationValidator: @escaping @Sendable (Int32) -> Bool = { _ in true }
) -> Task<VendorCharonControlReceipt, Never> {
  Task {
    await controlTransport(factory).emergencyStop(
      timeoutMilliseconds: 500,
      expectedRunningPredicate: { true },
      peerGenerationValidator: peerGenerationValidator
    )
  }
}

private final class EmergencyStopGate: @unchecked Sendable {
  private let lock = NSLock()
  private let factory: CharonControlDriverFactory
  private let result: Bool
  private var calls = 0
  private var observedFactoryCalls: [Int] = []

  init(factory: CharonControlDriverFactory, result: Bool) {
    self.factory = factory
    self.result = result
  }

  func evaluate() -> Bool {
    lock.withLock {
      calls += 1
      observedFactoryCalls.append(factory.callCount)
      return result
    }
  }

  var callCount: Int { lock.withLock { calls } }
  var factoryCallsObserved: [Int] { lock.withLock { observedFactoryCalls } }
}
