import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonAsyncGenerationValidationTests {
  @Test func hangingStartValidatorTimesOutAndLateSuccessIsIgnored() async throws {
    let factory = CharonControlDriverFactory()
    let gate = AsyncValidationGate()
    let pending = controlTransport(factory).beginStart(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 100,
      peerGenerationValidator: gate.evaluate
    )
    let task = Task { await pending.result() }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    #expect(await waitForControl { gate.isStarted })

    let result = await task.value
    #expect(result.receipt.outcome == .timeout)
    #expect(!result.receipt.transportAcknowledged)
    #expect(result.lease == nil)
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)

    gate.resolve(true)
    await Task.yield()
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func cancellationDuringStartValidationIsTerminal() async throws {
    let factory = CharonControlDriverFactory()
    let gate = AsyncValidationGate()
    let snapshot = try ControlSnapshotFixture().snapshot()
    let task = Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: gate.evaluate
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    #expect(await waitForControl { gate.isStarted })
    task.cancel()

    let result = await task.value
    #expect(result.receipt.outcome == .cancelled)
    #expect(!result.receipt.transportAcknowledged)
    #expect(result.lease == nil)
    gate.resolve(true)
    await Task.yield()
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func suspendedStartValidatorResumesWithoutQueueDeadlock() async throws {
    let factory = CharonControlDriverFactory()
    let gate = AsyncValidationGate()
    let snapshot = try ControlSnapshotFixture().snapshot()
    let task = Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: gate.evaluate
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    #expect(await waitForControl { gate.isStarted })
    gate.resolve(true)
    let start = await task.value
    let lease = try #require(start.lease)
    #expect(start.receipt.transportAcknowledged)

    let stopTask = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    #expect((await stopTask.value).transportAcknowledged)
  }

  @Test func emergencyFalseValidatorNeverSendsStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = AsyncValidationGate()
    let task = emergencyStopTask(factory, peerGenerationValidator: gate.evaluate)
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { gate.isStarted })
    gate.resolve(false)

    let receipt = await task.value
    #expect(receipt.outcome == .peerGenerationMismatch)
    #expect(!receipt.requestSent)
    #expect(factory.driver.stopCount == 0)
  }

  @Test func emergencyValidatorTimeoutNeverSendsStopAndIgnoresLateSuccess() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = AsyncValidationGate()
    let task = Task {
      await emergencyTransport(factory).emergencyStop(
        timeoutMilliseconds: 100,
        expectedRunningPredicate: { true },
        peerGenerationValidator: gate.evaluate
      )
    }
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { gate.isStarted })

    let receipt = await task.value
    #expect(receipt.outcome == .timeout)
    #expect(!receipt.requestSent)
    #expect(factory.driver.stopCount == 0)
    gate.resolve(true)
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
  }

  @Test func emergencyPreflightTimeoutCreatesNoSession() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = AsyncValidationGate()
    let receipt = await emergencyTransport(factory).emergencyStop(
      timeoutMilliseconds: 100,
      expectedRunningPredicate: gate.evaluate,
      peerGenerationValidator: { true }
    )

    #expect(gate.isStarted)
    #expect(receipt.outcome == .timeout)
    #expect(factory.callCount == 0)
    #expect(factory.driver.stopCount == 0)
    gate.resolve(true)
  }
}

private final class AsyncValidationGate: @unchecked Sendable {
  private let lock = NSLock()
  private var started = false
  private var resolution: Bool?
  private var continuation: CheckedContinuation<Bool, Never>?

  func evaluate() async -> Bool {
    await withCheckedContinuation { continuation in
      let immediate = lock.withLock { () -> Bool? in
        started = true
        if let resolution { return resolution }
        self.continuation = continuation
        return nil
      }
      if let immediate { continuation.resume(returning: immediate) }
    }
  }

  func resolve(_ value: Bool) {
    let continuation = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
      guard resolution == nil else { return nil }
      resolution = value
      defer { self.continuation = nil }
      return self.continuation
    }
    continuation?.resume(returning: value)
  }

  var isStarted: Bool { lock.withLock { started } }
}
