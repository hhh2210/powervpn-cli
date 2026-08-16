import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonProvisionalStopCapabilityTests {
  @Test func cancellationAfterSubmissionCanStopSameSessionExactlyOnce() async throws {
    let factory = CharonControlDriverFactory()
    let task = try startTask(factory)
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    task.cancel()

    let result = await task.value
    #expect(result.receipt.outcome == .cancelled)
    try await expectExactlyOneSameSessionStop(result, factory: factory)
  }

  @Test func timeoutAfterSubmissionCanStopSameSessionExactlyOnce() async throws {
    let factory = CharonControlDriverFactory()
    let task = Task {
      await controlTransport(factory).start(
        snapshot: try ControlSnapshotFixture().snapshot(),
        timeoutMilliseconds: 10,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.replyUnavailable, at: 0)
    let result = try await task.value

    #expect(result.receipt.outcome == .timeout)
    #expect(result.receipt.replyUnavailableObserved)
    #expect(result.receipt.completionSource == .timeout)
    #expect(factory.driver.cancelCount == 0)
    try await expectExactlyOneSameSessionStop(result, factory: factory)
  }

  @Test func generationMismatchCanStopSameSessionExactlyOnce() async throws {
    let factory = CharonControlDriverFactory()
    let task = try startTask(factory, validator: { false })
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)

    let result = await task.value
    #expect(result.receipt.outcome == .peerGenerationMismatch)
    try await expectExactlyOneSameSessionStop(result, factory: factory)
  }

  @Test func preSubmissionRejectionHasNoCapabilityAndNoStop() async throws {
    let factory = CharonControlDriverFactory()
    factory.driver.invalidateSession()

    let result = await controlTransport(factory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true }
    )

    #expect(result.receipt.outcome == .connectionInvalid)
    #expect(!result.receipt.requestSent)
    #expect(result.provisionalStopCapability == nil)
    #expect(factory.driver.submitCount == 0)
  }

  @Test func terminalEventSealsProvisionalSessionBeforeStop() async throws {
    let factory = CharonControlDriverFactory()
    let result = await controlTransport(factory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 5,
      peerGenerationValidator: { true }
    )
    let capability = try #require(result.provisionalStopCapability)
    factory.driver.emitConnection(.connectionInvalid)
    #expect(await waitForControl { factory.driver.cancelCount == 1 })

    let stop = await capability.stop(timeoutMilliseconds: 500)

    #expect(stop.outcome == .leaseClosed)
    #expect(!stop.requestSent)
    #expect(!stop.transportAcknowledged)
    #expect(!stop.cleanupEstablished)
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func rejectedProvisionalStopDoesNotClaimSubmission() async throws {
    let factory = CharonControlDriverFactory()
    let result = await controlTransport(factory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 5,
      peerGenerationValidator: { true }
    )
    let capability = try #require(result.provisionalStopCapability)
    factory.driver.rejectFutureSubmissions()

    let stop = await capability.stop(timeoutMilliseconds: 500)

    #expect(stop.outcome == .connectionInvalid)
    #expect(!stop.requestSent)
    #expect(!stop.transportAcknowledged)
    #expect(!stop.cleanupEstablished)
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func acknowledgedStartKeepsOnlyNormalRetainedLease() async throws {
    let factory = CharonControlDriverFactory()
    let task = try startTask(factory)
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)

    let result = await task.value

    #expect(result.receipt.transportAcknowledged)
    #expect(result.lease != nil)
    #expect(result.provisionalStopCapability == nil)
  }

  private func expectExactlyOneSameSessionStop(
    _ result: VendorCharonStartControlResult,
    factory: CharonControlDriverFactory
  ) async throws {
    #expect(result.receipt.requestSent)
    #expect(!result.receipt.connectionRetained)
    #expect(!result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    let capability = try #require(result.provisionalStopCapability)

    let first = Task { await capability.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    let duplicate = await capability.stop(timeoutMilliseconds: 500)
    #expect(duplicate.outcome == .leaseClosed)
    #expect(!duplicate.requestSent)
    #expect(!duplicate.connectionRetained)

    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let stop = await first.value
    #expect(stop.outcome == .transportAcknowledged)
    #expect(stop.requestSent)
    #expect(stop.transportAcknowledged)
    #expect(!stop.cleanupEstablished)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.callCount == 1)
    #expect(factory.driver.cancelCount == 0)
    withExtendedLifetime(capability) {}
  }

  private func startTask(
    _ factory: CharonControlDriverFactory,
    validator: @escaping @Sendable () async -> Bool = { true }
  ) throws -> Task<VendorCharonStartControlResult, Never> {
    let snapshot = try ControlSnapshotFixture().snapshot()
    return Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: validator
      )
    }
  }
}
