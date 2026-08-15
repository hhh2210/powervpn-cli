import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonControlLifecycleTests {
  @Test func beginStartSubmitsBeforeBorrowMaterialExpires() async throws {
    let fixture = ControlSnapshotFixture()
    let snapshot = try fixture.snapshot()
    let factory = CharonControlDriverFactory()

    let pending = controlTransport(factory).beginStart(
      snapshot: snapshot,
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true }
    )

    #expect(factory.callCount == 1)
    #expect(factory.driver.submitCount == 1)
    #expect(factory.driver.observations.first?.exactStartShape == true)
    fixture.session.failBorrows()
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let result = await pending.result()

    #expect(result.receipt.outcome == .transportAcknowledged)
    #expect(result.receipt.requestSent)
    #expect(result.receipt.connectionRetained)
    #expect(result.lease != nil)
    _ = result.lease
  }

  @Test func startAcknowledgementRetainsConnectionUntilSameDriverStops() async throws {
    let factory = CharonControlDriverFactory()
    let transport = controlTransport(factory)
    let fixture = ControlSnapshotFixture()
    let snapshot = try fixture.snapshot()
    let startTask = Task {
      await transport.start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitConnection(.emptyDispatcherTail)
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let start = await startTask.value

    #expect(start.receipt.outcome == .transportAcknowledged)
    #expect(start.receipt.requestSent)
    #expect(start.receipt.transportAcknowledged)
    #expect(start.receipt.emptyReplyObserved)
    #expect(start.receipt.dispatcherTailEventCount == 1)
    #expect(start.receipt.peerGenerationValidated)
    #expect(start.receipt.connectionRetained)
    #expect(!start.receipt.connectionCancelRequested)
    #expect(start.receipt.helperMayHaveMutated)
    #expect(start.stopContext != nil)
    #expect(!start.receipt.helperSuccessEstablished)
    #expect(factory.callCount == 1)
    #expect(factory.driver.cancelCount == 0)
    #expect(
      factory.driver.observations == [
        ControlEnvelopeObservation(
          operation: "start_connection",
          exactStartShape: true,
          exactStopShape: false,
          gateway: "synthetic-gateway"
        )
      ])

    let lease = try #require(start.lease)
    fixture.gateway.failBorrows()
    let connected = VendorCharonStatusSignal(type: 1, phase: 2, state: 5)
    factory.driver.emitConnection(.status(connected))
    #expect(
      await waitForControl {
        lease.observation.statusEventCount == 1
          && lease.observation.latestStatus == connected
      })

    let stopTask = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let stop = await stopTask.value

    #expect(stop.outcome == .transportAcknowledged)
    #expect(stop.requestSent)
    #expect(stop.transportAcknowledged)
    #expect(!stop.connectionRetained)
    #expect(stop.connectionCancelRequested)
    #expect(!stop.helperSuccessEstablished)
    #expect(factory.callCount == 1)
    #expect(factory.driver.cancelCount == 1)
    #expect(factory.driver.observations.last?.exactStopShape == true)
    #expect(factory.driver.observations.last?.gateway == "synthetic-gateway")
    #expect(
      factory.driver.observations.first?.gateway
        == factory.driver.observations.last?.gateway
    )
    #expect(
      VendorCharonStopContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "stop_connection"),
      ])

    let repeated = await lease.stop(timeoutMilliseconds: 500)
    #expect(repeated.outcome == .leaseClosed)
    #expect(!repeated.requestSent)
    #expect(!repeated.connectionCancelRequested)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func leaseDeinitPerformsEmergencyCancelWithoutStopAcknowledgement() async throws {
    let factory = CharonControlDriverFactory()
    let transport = controlTransport(factory)
    var lease: VendorCharonControlLease?
    do {
      let snapshot = try ControlSnapshotFixture().snapshot()
      let task = Task {
        await transport.start(
          snapshot: snapshot,
          timeoutMilliseconds: 500,
          peerGenerationValidator: { true }
        )
      }
      #expect(await waitForControl { factory.driver.submitCount == 1 })
      factory.driver.emitReply(.emptyAcknowledgement, at: 0)
      let result = await task.value
      lease = result.lease
      #expect(lease != nil)
      #expect(result.receipt.connectionRetained)
      #expect(factory.driver.cancelCount == 0)
    }

    lease = nil
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
    #expect(factory.driver.submitCount == 1)
  }

  @Test func concurrentStopHasOneWinnerAndNeverOverwritesContinuation() async throws {
    let factory = CharonControlDriverFactory()
    let snapshot = try ControlSnapshotFixture().snapshot()
    let startTask = Task {
      await controlTransport(factory).start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let start = await startTask.value
    let lease = try #require(start.lease)

    let first = Task { await lease.stop(timeoutMilliseconds: 500) }
    let second = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let receipts = [await first.value, await second.value]

    #expect(receipts.map(\.outcome).filter { $0 == .transportAcknowledged }.count == 1)
    #expect(receipts.map(\.outcome).filter { $0 == .leaseClosed }.count == 1)
    #expect(receipts.filter(\.requestSent).count == 1)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func cancellingConcurrentStopLoserCannotCancelWinner() async throws {
    let factory = CharonControlDriverFactory()
    let snapshot = try ControlSnapshotFixture().snapshot()
    let pending = controlTransport(factory).beginStart(
      snapshot: snapshot,
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true }
    )
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let start = await pending.result()
    let lease = try #require(start.lease)

    let winner = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    let loser = Task { await lease.stop(timeoutMilliseconds: 500) }
    loser.cancel()
    let loserReceipt = await loser.value
    #expect(loserReceipt.outcome == .leaseClosed || loserReceipt.outcome == .cancelled)
    #expect(!loserReceipt.requestSent)
    #expect(factory.driver.cancelCount == 0)

    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let winnerReceipt = await winner.value
    #expect(winnerReceipt.outcome == .transportAcknowledged)
    #expect(winnerReceipt.requestSent)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func invalidTimeoutAndPreCancelledStartNeverEncodeOrCreateDriver() async throws {
    let invalidFactory = CharonControlDriverFactory()
    let invalid = await controlTransport(invalidFactory).start(
      snapshot: try ControlSnapshotFixture().snapshot(),
      timeoutMilliseconds: 0,
      peerGenerationValidator: { true }
    )
    #expect(invalid.receipt.outcome == .invalidTimeout)
    #expect(!invalid.receipt.requestSent)
    #expect(invalidFactory.callCount == 0)

    let cancelledFactory = CharonControlDriverFactory()
    let cancelledSnapshot = try ControlSnapshotFixture().snapshot()
    let cancelled = await Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return await controlTransport(cancelledFactory).start(
        snapshot: cancelledSnapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }.value
    #expect(cancelled.receipt.outcome == .cancelled)
    #expect(!cancelled.receipt.requestSent)
    #expect(cancelledFactory.callCount == 0)
  }

  @Test func encodingFailureNeverCreatesDriverOrClaimsSubmission() async throws {
    let fixture = ControlSnapshotFixture()
    let snapshot = try fixture.snapshot()
    fixture.session.failBorrows()
    let factory = CharonControlDriverFactory()

    let result = await controlTransport(factory).start(
      snapshot: snapshot,
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true }
    )

    #expect(result.receipt.outcome == .snapshotEncodingFailed)
    #expect(result.receipt.encodingError == .textMaterialUnavailable(.sessionID))
    #expect(!result.receipt.requestSent)
    #expect(!result.receipt.helperMayHaveMutated)
    #expect(!result.receipt.connectionCancelRequested)
    #expect(result.lease == nil)
    #expect(factory.callCount == 0)
    #expect(factory.driver.submitCount == 0)
    #expect(factory.driver.cancelCount == 0)
  }
  @Test func submittedStartContextCarriesIntoAuthenticatedEmergencyStop() async throws {
    let normalFactory = CharonControlDriverFactory()
    let emergencyFactory = EmergencyConnectionDriverFactory()
    let transport = RawVendorCharonControlTransport(
      driverFactory: normalFactory.make,
      emergencyDriverFactory: emergencyFactory.make
    )
    let fixture = ControlSnapshotFixture()
    let snapshot = try fixture.snapshot()
    let startTask = Task {
      await transport.start(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { normalFactory.driver.submitCount == 1 })
    normalFactory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let start = await startTask.value
    let stopContext = try #require(start.stopContext)
    fixture.gateway.failBorrows()

    let stopTask = Task {
      await transport.emergencyStop(
        timeoutMilliseconds: 500,
        stopContext: stopContext,
        expectedRunningPredicate: { true },
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { emergencyFactory.driver.probeCount == 1 })
    emergencyFactory.driver.emitProbeReply(.emptyAcknowledgement)
    emergencyFactory.driver.emitProbeBusiness()
    #expect(await waitForControl { emergencyFactory.driver.stopCount == 1 })
    #expect(
      emergencyFactory.driver.observations == [
        .getVersion,
        .stopConnection(gateway: "synthetic-gateway"),
      ])
    emergencyFactory.driver.emitStopReply(.emptyAcknowledgement)
    #expect((await stopTask.value).transportAcknowledged)
    _ = start.lease
  }

}
