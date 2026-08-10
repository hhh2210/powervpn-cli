import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonControlStatusWaitTests {
  @Test func connectedStatusBeforeWaitReturnsImmediately() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5)))
    #expect(await waitForControl { lease.observation.statusEventCount == 1 })

    let result = await lease.waitForConnectedStatus(timeoutMilliseconds: 500)

    #expect(result.outcome == .connected)
    #expect(result.statusEventCount == 1)
    #expect(result.latestClassification == .connected)
    #expect(result.terminalOutcome == nil)
    #expect(!lease.statusWaitPending)
    #expect(factory.driver.cancelCount == 0)
    await stop(lease, factory: factory)
  }

  @Test func statusDuringWaitIgnoresUnclassifiedThenReturnsConnected() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    let task = Task { await lease.waitForConnectedStatus(timeoutMilliseconds: 500) }
    #expect(await waitForControl { lease.statusWaitPending })

    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 99)))
    #expect(
      await waitForControl {
        lease.observation.statusEventCount == 1 && lease.statusWaitPending
      })
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5)))
    let result = await task.value

    #expect(result.outcome == .connected)
    #expect(result.statusEventCount == 2)
    #expect(result.latestClassification == .connected)
    #expect(result.terminalOutcome == nil)
    #expect(factory.driver.cancelCount == 0)
    await stop(lease, factory: factory)
  }

  @Test func disconnectedStatusBeforeWaitReturnsImmediately() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 7)))
    #expect(await waitForControl { lease.observation.statusEventCount == 1 })

    let result = await lease.waitForConnectedStatus(timeoutMilliseconds: 500)

    #expect(result.outcome == .disconnected)
    #expect(result.statusEventCount == 1)
    #expect(result.latestClassification == .disconnected)
    #expect(result.terminalOutcome == nil)
    #expect(factory.driver.cancelCount == 0)
    await stop(lease, factory: factory)
  }

  @Test func terminalConnectionEventSealsPendingWait() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    let task = Task { await lease.waitForConnectedStatus(timeoutMilliseconds: 500) }
    #expect(await waitForControl { lease.statusWaitPending })

    factory.driver.invalidateSession()
    let result = await task.value

    #expect(result.outcome == .terminalError)
    #expect(result.statusEventCount == 0)
    #expect(result.latestClassification == nil)
    #expect(result.terminalOutcome == .connectionInvalid)
    #expect(factory.driver.cancelCount == 1)
    let stopped = await lease.stop(timeoutMilliseconds: 500)
    #expect(stopped.outcome == .leaseClosed)
    #expect(!stopped.requestSent)
  }

  @Test func timeoutEndsOnlyWaitAndRetainsConnection() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)

    let result = await lease.waitForConnectedStatus(timeoutMilliseconds: 5)

    #expect(result.outcome == .timeout)
    #expect(result.statusEventCount == 0)
    #expect(result.latestClassification == nil)
    #expect(result.terminalOutcome == nil)
    #expect(!lease.statusWaitPending)
    #expect(factory.driver.cancelCount == 0)
    await stop(lease, factory: factory)
  }

  @Test func cancellingWaitStillAllowsSameLeaseStop() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    let task = Task { await lease.waitForConnectedStatus(timeoutMilliseconds: 500) }
    #expect(await waitForControl { lease.statusWaitPending })

    task.cancel()
    let result = await task.value

    #expect(result.outcome == .cancelled)
    #expect(result.statusEventCount == 0)
    #expect(result.terminalOutcome == nil)
    #expect(!lease.statusWaitPending)
    #expect(factory.driver.cancelCount == 0)
    await stop(lease, factory: factory)
  }

  @Test func secondConcurrentWaiterFailsClosedWithoutReplacingFirst() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    let first = Task { await lease.waitForConnectedStatus(timeoutMilliseconds: 500) }
    #expect(await waitForControl { lease.statusWaitPending })

    let second = await lease.waitForConnectedStatus(timeoutMilliseconds: 500)

    #expect(second.outcome == .leaseClosed)
    #expect(second.statusEventCount == 0)
    #expect(second.terminalOutcome == nil)
    #expect(lease.statusWaitPending)
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5)))
    let firstResult = await first.value
    #expect(firstResult.outcome == .connected)
    #expect(firstResult.statusEventCount == 1)
    #expect(factory.driver.cancelCount == 0)
    await stop(lease, factory: factory)
  }

  @Test func stopSubmissionAtomicallyCapturesLatestStatus() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeLease(factory)
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5)))
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 7)))
    #expect(await waitForControl { lease.observation.statusEventCount == 2 })

    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let result = await task.value

    #expect(result.outcome == .transportAcknowledged)
    #expect(result.requestSent)
    #expect(result.statusEventCount == 2)
    #expect(result.statusAtSubmission == .disconnected)
    #expect(factory.driver.cancelCount == 1)
  }
}

private func activeLease(
  _ factory: CharonControlDriverFactory
) async throws -> VendorCharonControlLease {
  let pending = controlTransport(factory).beginStart(
    snapshot: try ControlSnapshotFixture().snapshot(),
    timeoutMilliseconds: 500,
    peerGenerationValidator: { true }
  )
  #expect(factory.driver.submitCount == 1)
  factory.driver.emitReply(.emptyAcknowledgement, at: 0)
  let result = await pending.result()
  #expect(result.receipt.outcome == .transportAcknowledged)
  return try #require(result.lease)
}

private func stop(
  _ lease: VendorCharonControlLease,
  factory: CharonControlDriverFactory
) async {
  let task = Task { await lease.stop(timeoutMilliseconds: 500) }
  #expect(await waitForControl { factory.driver.submitCount == 2 })
  factory.driver.emitReply(.emptyAcknowledgement, at: 1)
  let result = await task.value
  #expect(result.outcome == .transportAcknowledged)
  #expect(result.requestSent)
  #expect(factory.driver.cancelCount == 1)
}
