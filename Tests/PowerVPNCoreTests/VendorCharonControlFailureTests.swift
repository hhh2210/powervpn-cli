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
    #expect(result.provisionalStopCapability == nil)
    #expect(factory.driver.submitCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func generationMismatchRejectsEmptyReplyAndRetainsCleanupCapability() async throws {
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
    #expect(!result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(result.provisionalStopCapability != nil)
    #expect(factory.driver.cancelCount == 0)
  }

  @Test func timeoutRetainsCleanupCapabilityAndLateReplyCannotCreateLease() async throws {
    let factory = CharonControlDriverFactory()
    let result = await controlTransport(factory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 5,
      peerGenerationValidator: { true }
    )

    #expect(result.receipt.outcome == .timeout)
    #expect(result.receipt.requestSent)
    #expect(result.receipt.helperMayHaveMutated)
    #expect(!result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(result.provisionalStopCapability != nil)
    #expect(factory.driver.cancelCount == 0)
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    await Task.yield()
    #expect(factory.driver.cancelCount == 0)
  }

  @Test func taskCancellationAfterSubmissionKeepsTruthfulCleanupCapability() async throws {
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
    #expect(!result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(result.provisionalStopCapability != nil)
    #expect(factory.driver.cancelCount == 0)
    factory.driver.emitConnection(.connectionInvalid)
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func replyAndConnectionErrorsAreClosedAndNeverAcknowledged() async throws {
    let replyCases:
      [(
        VendorCharonControlReplyEvent, VendorCharonControlOutcome, Bool
      )] = [
        (.peerCodeSigningRequirement, .peerCodeSigningRequirement, true),
        (.unexpectedXPCError, .unexpectedXPCError, true),
        (.unexpectedPayload, .unexpectedReplyPayload, false),
      ]
    for (event, expected, sessionSealed) in replyCases {
      let factory = CharonControlDriverFactory()
      let task = try startTask(factory)
      #expect(await waitForControl { factory.driver.submitCount == 1 })
      factory.driver.emitReply(event, at: 0)
      let result = await task.value
      #expect(result.receipt.outcome == expected)
      #expect(!result.receipt.transportAcknowledged)
      #expect(result.receipt.requestSent)
      #expect(result.provisionalStopCapability != nil)
      #expect(result.receipt.connectionCancelRequested == sessionSealed)
      #expect(factory.driver.cancelCount == (sessionSealed ? 1 : 0))
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
      #expect(result.provisionalStopCapability != nil)
      #expect(result.receipt.connectionCancelRequested)
      #expect(factory.driver.cancelCount == 1)
    }
  }

  @Test func submittedStopTimeoutTransfersDriverToDrain() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeFailureLease(factory, drainScheduler: scheduler.schedule)

    let task = Task { await lease.stop(timeoutMilliseconds: 10) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.replyUnavailable, at: 1)
    let stop = await task.value
    #expect(stop.outcome == .timeout)
    #expect(stop.requestSent)
    #expect(stop.helperMayHaveMutated)
    #expect(stop.replyUnavailableObserved)
    #expect(stop.completionSource == .timeout)
    #expect(!stop.connectionCancelRequested)
    #expect(!stop.connectionRetained)
    #expect(scheduler.isArmed)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 0)

    let repeated = await lease.stop(timeoutMilliseconds: 500)
    #expect(repeated.outcome == .leaseClosed)
    #expect(!repeated.requestSent)
    #expect(!repeated.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func submittedStopCallerCancellationTransfersDriverToDrain() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeFailureLease(factory, drainScheduler: scheduler.schedule)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(receipt.requestSent)
    #expect(receipt.helperMayHaveMutated)
    #expect(receipt.completionSource == .callerCancel)
    #expect(!receipt.connectionCancelRequested)
    #expect(!receipt.connectionRetained)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    await Task.yield()
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func unsentStopFailureDoesNotArmDrain() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeFailureLease(factory, drainScheduler: scheduler.schedule)
    factory.driver.rejectFutureSubmissions()

    let receipt = await lease.stop(timeoutMilliseconds: 500)

    #expect(receipt.outcome == .connectionInvalid)
    #expect(!receipt.requestSent)
    #expect(receipt.connectionCancelRequested)
    #expect(!scheduler.isArmed)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func timeoutDoesNotMasqueradeAsAcknowledgement() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeFailureLease(factory, drainScheduler: scheduler.schedule)

    let receipt = await lease.stop(timeoutMilliseconds: 10)

    #expect(receipt.outcome == .timeout)
    #expect(receipt.completionSource == .timeout)
    #expect(receipt.requestSent)
    #expect(!receipt.emptyReplyObserved)
    #expect(!receipt.peerGenerationValidated)
    #expect(!receipt.transportAcknowledged)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
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

  @Test func realConnectionTerminalStillCancels() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeFailureLease(factory, drainScheduler: scheduler.schedule)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitConnection(.connectionInvalid)
    let receipt = await task.value

    #expect(receipt.outcome == .connectionInvalid)
    #expect(receipt.completionSource == .connectionTerminal)
    #expect(receipt.requestSent)
    #expect(!receipt.emptyReplyObserved)
    #expect(!receipt.peerGenerationValidated)
    #expect(!receipt.transportAcknowledged)
    #expect(receipt.connectionCancelRequested)
    #expect(!scheduler.isArmed)
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

  private func activeFailureLease(
    _ factory: CharonControlDriverFactory,
    drainScheduler: @escaping VendorCharonConnectionDrainScheduler
  ) async throws -> VendorCharonControlLease {
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: factory.make,
      postStopDrainScheduler: drainScheduler
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: {}
    )
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    return try #require((await state.awaitStartResult()).lease)
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
