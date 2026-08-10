import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonControlFailureTests {
  @Test func invalidSessionRejectsStartBeforeSubmission() async throws {
    let factory = CharonControlDriverFactory()
    factory.driver.invalidateSession()

    let result = await controlTransport(factory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true }
    )

    #expect(result.receipt.outcome == .connectionInvalid)
    #expect(!result.receipt.requestSent)
    #expect(!result.receipt.emptyReplyObserved)
    #expect(result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(factory.driver.submitCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func generationMismatchRejectsEmptyReplyAndCancelsOnce() async throws {
    let factory = CharonControlDriverFactory()
    let snapshot = try ControlSnapshotFixture().snapshot()
    let task = Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { false }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let result = await task.value

    #expect(result.receipt.outcome == .peerGenerationMismatch)
    #expect(result.receipt.requestSent)
    #expect(result.receipt.emptyReplyObserved)
    #expect(!result.receipt.peerGenerationValidated)
    #expect(!result.receipt.transportAcknowledged)
    #expect(result.receipt.helperMayHaveMutated)
    #expect(result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func timeoutCancelsOnceAndLateReplyCannotCreateLease() async throws {
    let factory = CharonControlDriverFactory()
    let result = await controlTransport(factory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 5,
      peerGenerationValidator: { true }
    )

    #expect(result.receipt.outcome == .timeout)
    #expect(result.receipt.requestSent)
    #expect(result.receipt.helperMayHaveMutated)
    #expect(result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    await Task.yield()
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func taskCancellationAfterSubmissionCancelsOnceAndKeepsTruthfulReceipt() async throws {
    let factory = CharonControlDriverFactory()
    let snapshot = try ControlSnapshotFixture().snapshot()
    let task = Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    task.cancel()
    let result = await task.value

    #expect(result.receipt.outcome == .cancelled)
    #expect(result.receipt.requestSent)
    #expect(result.receipt.helperMayHaveMutated)
    #expect(result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitConnection(.connectionInvalid)
    await Task.yield()
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func replyAndConnectionErrorsAreClosedAndNeverAcknowledged() async throws {
    let replyCases: [(VendorCharonControlReplyEvent, VendorCharonControlOutcome)] = [
      (.connectionInterrupted, .connectionInterrupted),
      (.connectionInvalid, .connectionInvalid),
      (.peerCodeSigningRequirement, .peerCodeSigningRequirement),
      (.unexpectedXPCError, .unexpectedXPCError),
      (.unexpectedPayload, .unexpectedReplyPayload),
    ]
    for (event, expected) in replyCases {
      let factory = CharonControlDriverFactory()
      let task = try startTask(factory)
      #expect(await waitForControl { factory.driver.submitCount == 1 })
      factory.driver.emitReply(event, at: 0)
      let result = await task.value
      #expect(result.receipt.outcome == expected)
      #expect(!result.receipt.transportAcknowledged)
      #expect(result.receipt.requestSent)
      #expect(factory.driver.cancelCount == 1)
    }

    let connectionCases: [(VendorCharonControlConnectionEvent, VendorCharonControlOutcome)] = [
      (.connectionInterrupted, .connectionInterrupted),
      (.connectionInvalid, .connectionInvalid),
      (.peerCodeSigningRequirement, .peerCodeSigningRequirement),
      (.unexpectedXPCError, .unexpectedXPCError),
      (.unexpectedConnectionEvent, .unexpectedConnectionEvent),
      (.unexpectedDictionary, .unexpectedConnectionEvent),
    ]
    for (event, expected) in connectionCases {
      let factory = CharonControlDriverFactory()
      let task = try startTask(factory)
      #expect(await waitForControl { factory.driver.submitCount == 1 })
      factory.driver.emitConnection(event)
      let result = await task.value
      #expect(result.receipt.outcome == expected)
      #expect(!result.receipt.transportAcknowledged)
      #expect(result.receipt.requestSent)
      #expect(factory.driver.cancelCount == 1)
    }
  }

  @Test func stopTimeoutClosesLeaseAndCancelsSameDriverOnce() async throws {
    let factory = CharonControlDriverFactory()
    let start = try await acknowledgedStart(factory)
    let lease = try #require(start.lease)

    let stop = await lease.stop(timeoutMilliseconds: 5)
    #expect(stop.outcome == .timeout)
    #expect(stop.requestSent)
    #expect(stop.helperMayHaveMutated)
    #expect(stop.connectionCancelRequested)
    #expect(!stop.connectionRetained)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 1)

    let repeated = await lease.stop(timeoutMilliseconds: 500)
    #expect(repeated.outcome == .leaseClosed)
    #expect(!repeated.requestSent)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func stopCancellationAfterSubmissionClosesLeaseAndCancelsOnce() async throws {
    let factory = CharonControlDriverFactory()
    let start = try await acknowledgedStart(factory)
    let lease = try #require(start.lease)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(receipt.requestSent)
    #expect(receipt.helperMayHaveMutated)
    #expect(receipt.connectionCancelRequested)
    #expect(!receipt.connectionRetained)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    await Task.yield()
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func invalidatedSessionBeforeStopCannotSubmit() async throws {
    let factory = CharonControlDriverFactory()
    let start = try await acknowledgedStart(factory)
    let lease = try #require(start.lease)
    factory.driver.invalidateSession()
    #expect(
      await waitForControl {
        lease.observation.terminalConnectionOutcome == .connectionInvalid
      })

    let receipt = await lease.stop(timeoutMilliseconds: 500)

    #expect(receipt.outcome == .leaseClosed)
    #expect(!receipt.requestSent)
    #expect(!receipt.emptyReplyObserved)
    #expect(!receipt.peerGenerationValidated)
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func invalidationAfterStopSubmissionCannotAcknowledge() async throws {
    let factory = CharonControlDriverFactory()
    let start = try await acknowledgedStart(factory)
    let lease = try #require(start.lease)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.invalidateSession()
    let receipt = await task.value

    #expect(receipt.outcome == .connectionInvalid)
    #expect(receipt.requestSent)
    #expect(!receipt.emptyReplyObserved)
    #expect(!receipt.peerGenerationValidated)
    #expect(!receipt.transportAcknowledged)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func activeUnexpectedEventIsRetainedAsTerminalValueFreeObservation() async throws {
    let factory = CharonControlDriverFactory()
    let start = try await acknowledgedStart(factory)
    let lease = try #require(start.lease)

    factory.driver.emitConnection(.unexpectedDictionary)
    #expect(
      await waitForControl {
        lease.observation.terminalConnectionOutcome == .unexpectedConnectionEvent
      })
    #expect(lease.observation.unexpectedDictionaryEventCount == 1)
    #expect(factory.driver.cancelCount == 1)

    let stop = await lease.stop(timeoutMilliseconds: 500)
    #expect(stop.outcome == .leaseClosed)
    #expect(!stop.requestSent)
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  private func startTask(
    _ factory: CharonControlDriverFactory
  ) throws -> Task<VendorCharonStartControlResult, Never> {
    let snapshot = try ControlSnapshotFixture().snapshot()
    return Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
  }

  private func acknowledgedStart(
    _ factory: CharonControlDriverFactory
  ) async throws -> VendorCharonStartControlResult {
    let task = try startTask(factory)
    _ = await waitForControl { factory.driver.submitCount == 1 }
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    return await task.value
  }
}
