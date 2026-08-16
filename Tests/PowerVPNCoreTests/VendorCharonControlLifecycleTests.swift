import Dispatch
import Testing
@preconcurrency import XPC

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
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let start = await startTask.value

    #expect(start.receipt.outcome == .transportAcknowledged)
    #expect(start.receipt.requestSent)
    #expect(start.receipt.transportAcknowledged)
    #expect(start.receipt.emptyReplyObserved)
    #expect(start.receipt.dispatcherTailEventCount == 0)
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
          exactNCRouteToggleShape: false,
          ncRouteEnabled: nil,
          tunnelName: nil,
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
    #expect(!stop.connectionCancelRequested)
    #expect(!stop.helperSuccessEstablished)
    #expect(factory.callCount == 1)
    #expect(factory.driver.cancelCount == 0)
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
    #expect(factory.driver.cancelCount == 0)
  }

  @Test func replyUnavailableThenOrdinaryStartAcknowledgementRetainsLease() async throws {
    let factory = CharonControlDriverFactory()
    let task = Task {
      await controlTransport(factory).start(
        snapshot: try ControlSnapshotFixture().snapshot(),
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 1 })

    factory.driver.emitReply(.replyUnavailable, at: 0)
    factory.driver.emitConnectionDictionary(xpc_dictionary_create(nil, nil, 0))
    let start = try await task.value

    #expect(start.receipt.outcome == .transportAcknowledged)
    #expect(start.receipt.replyUnavailableObserved)
    #expect(start.receipt.completionSource == .replyUnavailableThenOrdinary)
    #expect(start.receipt.connectionRetained)
    #expect(!start.receipt.connectionCancelRequested)
    #expect(factory.driver.cancelCount == 0)
    withExtendedLifetime(start.lease) {}
  }

  @Test func replyUnavailableThenOrdinaryStopAcknowledgementUsesBoundedDrain()
    async throws
  {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeLease(factory, drainScheduler: scheduler.schedule)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitReply(.replyUnavailable, at: 1)
    factory.driver.emitConnectionDictionary(xpc_dictionary_create(nil, nil, 0))
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.replyUnavailableObserved)
    #expect(receipt.completionSource == .replyUnavailableThenOrdinary)
    #expect(!receipt.connectionRetained)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    withExtendedLifetime(lease) {}
  }

  @Test func disconnectedStatusAfterStopSubmissionAcknowledgesAndTransfersDrain()
    async throws
  {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeLease(factory, drainScheduler: scheduler.schedule)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitConnection(.status(VendorCharonStatusSignal(type: 1, phase: 2, state: 7)))
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.completionSource == .ordinaryConnection)
    #expect(receipt.statusEventCount == 1)
    #expect(!receipt.connectionRetained)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    withExtendedLifetime(lease) {}
  }

  @Test func nonDisconnectedStatusAfterStopSubmissionStillTimesOut() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeLease(factory, drainScheduler: scheduler.schedule)
    let task = Task { await lease.stop(timeoutMilliseconds: 20) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitConnection(.status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5)))
    let receipt = await task.value

    #expect(receipt.outcome == .timeout)
    #expect(receipt.requestSent)
    #expect(receipt.completionSource == .timeout)
    #expect(receipt.statusEventCount == 1)
    #expect(!receipt.connectionRetained)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    withExtendedLifetime(lease) {}
  }

  @Test func connectionTailAcknowledgesStartWithoutReplyAndKeepsLeaseUsable()
    async throws
  {
    let factory = CharonControlDriverFactory()
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: factory.make
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: {}
    )
    #expect(factory.driver.submitCount == 1)

    factory.driver.emitConnectionDictionary(xpc_dictionary_create(nil, nil, 0))
    let start = await state.awaitStartResult()
    let lease = try #require(start.lease)

    #expect(start.receipt.outcome == .transportAcknowledged)
    #expect(start.receipt.transportAcknowledged)
    #expect(start.receipt.requestSent)
    #expect(start.receipt.emptyReplyObserved)
    #expect(start.receipt.dispatcherTailEventCount == 1)
    #expect(start.receipt.incomingEventSignatures == ["1:connection:{}"])
    #expect(start.receipt.replySignatures.isEmpty)
    #expect(start.receipt.connectionRetained)
    #expect(factory.driver.cancelCount == 0)

    factory.driver.emitConnectionDictionary(xpc_dictionary_create(nil, nil, 0))
    #expect(
      await waitForControl {
        lease.observation.dispatcherTailEventCount == 2
      })
    #expect(factory.driver.cancelCount == 0)

    let statusTask = Task {
      await lease.waitForConnectedStatus(timeoutMilliseconds: 500)
    }
    #expect(await waitForControl { lease.statusWaitPending })
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5))
    )
    #expect((await statusTask.value).outcome == .connected)
    withExtendedLifetime(lease) {}
  }

  @Test func tailBeforeSubmissionAndInInactivePhasesCannotAcknowledge() throws {
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: CharonControlDriverFactory().make
    )

    let ignored = state.queue.sync { () -> (Bool, Bool, Bool, Bool) in
      state.handle(.emptyDispatcherTail)
      let idleIgnored: Bool
      if case .idle = state.phase {
        idleIgnored = !state.emptyReplyObserved
      } else {
        idleIgnored = false
      }

      state.phase = .starting
      state.requestSent = false
      state.handle(.emptyDispatcherTail)
      let stayedStarting: Bool
      if case .starting = state.phase {
        stayedStarting = !state.emptyReplyObserved && state.validation == nil
      } else {
        stayedStarting = false
      }

      state.phase = .provisional
      state.requestSent = true
      state.handle(.emptyDispatcherTail)
      let provisionalIgnored: Bool
      if case .provisional = state.phase {
        provisionalIgnored = !state.emptyReplyObserved
      } else {
        provisionalIgnored = false
      }

      state.phase = .active
      state.handle(.emptyDispatcherTail)
      let activeIgnored: Bool
      if case .active = state.phase {
        activeIgnored = !state.emptyReplyObserved
      } else {
        activeIgnored = false
      }
      state.phase = .idle
      state.requestSent = false
      return (idleIgnored, stayedStarting, provisionalIgnored, activeIgnored)
    }

    #expect(ignored.0)
    #expect(ignored.1)
    #expect(ignored.2)
    #expect(ignored.3)
    #expect(state.observation.dispatcherTailEventCount == 4)
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
  @Test func stopAcknowledgementReturnsBeforeBoundedDrainExpiry() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeLease(factory, drainScheduler: scheduler.schedule)

    let receipt = await acknowledgedStop(lease, factory: factory)

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)

    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
    #expect(scheduler.cancellationCount == 1)
  }

  @Test func connectionTailAcknowledgesStopAndTransfersBoundedDrain() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeLease(factory, drainScheduler: scheduler.schedule)
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitConnectionDictionary(xpc_dictionary_create(nil, nil, 0))
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.emptyReplyObserved)
    #expect(receipt.dispatcherTailEventCount == 1)
    #expect(receipt.incomingEventSignatures == ["1:connection:{}"])
    #expect(receipt.replySignatures.isEmpty)
    #expect(!receipt.connectionRetained)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)

    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
    #expect(scheduler.cancellationCount == 1)
    withExtendedLifetime(lease) {}
  }

  @Test func acknowledgedStopLeaseDeinitKeepsArmedDrain() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    var lease: VendorCharonControlLease? = try await activeLease(
      factory,
      drainScheduler: scheduler.schedule
    )
    let receipt = await acknowledgedStop(try #require(lease), factory: factory)
    #expect(receipt.outcome == .transportAcknowledged)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)

    lease = nil

    await Task.yield()
    #expect(scheduler.isArmed)
    #expect(scheduler.cancellationCount == 0)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
    #expect(scheduler.cancellationCount == 1)
  }
  @Test func postStopDrainWaitIgnoresTaskCancellationAndCompletesOnExpiry() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let lease = try await activeLease(factory, drainScheduler: scheduler.schedule)
    _ = await acknowledgedStop(lease, factory: factory)
    let completion = DrainCompletionProbe()
    let waiter = Task {
      await lease.awaitPostStopDrain()
      completion.mark()
    }

    waiter.cancel()
    await Task.yield()
    #expect(!completion.isComplete)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    await waiter.value
    #expect(completion.isComplete)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func callerCancellationAfterAcknowledgedStopDoesNotCollapseDrain() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let release = DispatchSemaphore(value: 0)
    let lease = try await activeLease(
      factory,
      drainScheduler: { queue, expiration in
        let cancelExpiration = scheduler.schedule(queue: queue, expiration: expiration)
        release.wait()
        return cancelExpiration
      }
    )
    let task = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    #expect(await waitForControl { scheduler.isArmed })
    task.cancel()
    release.signal()
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(!receipt.connectionCancelRequested)
    await Task.yield()
    #expect(scheduler.isArmed)
    #expect(scheduler.cancellationCount == 0)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
    #expect(scheduler.cancellationCount == 1)
  }

  @Test func drainExpiryIsExactlyOnceAcrossOwnerReleaseRaces() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    var lease: VendorCharonControlLease? = try await activeLease(
      factory,
      drainScheduler: scheduler.schedule
    )
    _ = await acknowledgedStop(try #require(lease), factory: factory)

    lease = nil
    await Task.yield()
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    scheduler.expire()

    #expect(await waitForControl { factory.driver.cancelCount == 1 })
    #expect(scheduler.cancellationCount == 1)
  }

  @Test func tunnelNameReportsDoNotAffectStartStopOrStatusWait() async throws {
    let factory = CharonControlDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: factory.make,
      postStopDrainScheduler: scheduler.schedule
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: {}
    )
    factory.driver.emitConnection(.tunnelNameReported(success: true))
    factory.driver.emitReply(.emptyAcknowledgement, at: 0)
    let start = await state.awaitStartResult()
    let lease = try #require(start.lease)
    #expect(start.receipt.outcome == .transportAcknowledged)

    let statusTask = Task {
      await lease.waitForConnectedStatus(timeoutMilliseconds: 500)
    }
    #expect(await waitForControl { lease.statusWaitPending })
    factory.driver.emitConnection(.tunnelNameReported(success: false))
    await Task.yield()
    #expect(lease.statusWaitPending)
    factory.driver.emitConnection(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 5))
    )
    let status = await statusTask.value
    #expect(status.outcome == .connected)
    #expect(status.statusEventCount == 1)

    let stopTask = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitConnection(.tunnelNameReported(success: true))
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let stop = await stopTask.value

    #expect(stop.outcome == .transportAcknowledged)
    #expect(stop.statusEventCount == 1)
    #expect(!stop.connectionCancelRequested)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func wireSignatureTimelineIsBoundedDedupedAndChannelOrdered() async throws {
    let factory = CharonControlDriverFactory()
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: factory.make
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: {}
    )

    for _ in 0..<2 {
      factory.driver.emitConnectionDictionary(diagnosticTunnelNameObject(nameKey: nil))
    }
    for index in 0..<20 {
      factory.driver.emitConnectionDictionary(
        diagnosticTunnelNameObject(nameKey: index.isMultiple(of: 2) ? "namev4" : "namev6")
      )
    }
    factory.driver.emitReplyDictionary(xpc_dictionary_create(nil, nil, 0), at: 0)
    let start = await state.awaitStartResult()

    #expect(start.receipt.outcome == .transportAcknowledged)
    #expect(start.receipt.incomingEventSignatures.count == 12)
    #expect(
      start.receipt.incomingEventSignatures.first
        == "1:connection:get_tun_name_success:bool")
    #expect(
      start.receipt.incomingEventSignatures.last
        == "12:connection:get_tun_name_success:bool,namev4:string")
    #expect(start.receipt.replySignatures == ["22:reply:{}"])
    #expect(state.observation.incomingEventSignatures == start.receipt.incomingEventSignatures)
    #expect(state.observation.replySignatures == start.receipt.replySignatures)
    #expect(start.receipt.unexpectedEventSignature == nil)
    #expect(
      !retainedStrings(in: start.receipt).contains {
        $0.contains("utun-value-must-not-escape")
      })
    withExtendedLifetime(start.lease) {}
  }

  @Test func acceptedAndRejectedEventSignaturesRetainNoValueBytes() async throws {
    let factory = CharonControlDriverFactory()
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: factory.make
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: {}
    )
    factory.driver.emitConnectionDictionary(
      diagnosticStatusObject(name: "status-value-must-not-escape")
    )
    let rejected = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(rejected, "mystery", "rejected-value-must-not-escape")
    factory.driver.emitConnectionDictionary(rejected)
    let start = await state.awaitStartResult()

    #expect(start.receipt.outcome == .unexpectedConnectionEvent)
    #expect(
      start.receipt.incomingEventSignatures == [
        "1:connection:name:string,phase:int64,state:int64,type:int64",
        "2:connection:mystery:string",
      ])
    #expect(start.receipt.replySignatures.isEmpty)
    #expect(start.receipt.unexpectedEventSignature == ["mystery:string"])
    #expect(state.observation.incomingEventSignatures == start.receipt.incomingEventSignatures)
    let retained = retainedStrings(in: (state.observation, start.receipt))
    #expect(!retained.contains("status-value-must-not-escape"))
    #expect(!retained.contains("rejected-value-must-not-escape"))
  }

  @Test func rejectedReplySignatureRecordsReplyChannelWithoutValues() async throws {
    let factory = CharonControlDriverFactory()
    let state = VendorCharonControlState(
      snapshot: try ControlSnapshotFixture().snapshot(),
      driverFactory: factory.make
    )
    try state.beginStartSynchronously(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: {}
    )
    let rejected = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(rejected, "payload", "reply-value-must-not-escape")
    factory.driver.emitReplyDictionary(rejected, at: 0)
    let start = await state.awaitStartResult()

    #expect(start.receipt.outcome == .unexpectedReplyPayload)
    #expect(start.receipt.incomingEventSignatures.isEmpty)
    #expect(start.receipt.replySignatures == ["1:reply:payload:string"])
    #expect(start.receipt.unexpectedEventSignature == nil)
    #expect(!retainedStrings(in: start.receipt).contains("reply-value-must-not-escape"))
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
    #expect((0...1).contains(factory.driver.cancelCount))
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
    #expect(factory.driver.cancelCount == 0)
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

private func activeLease(
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

private func acknowledgedStop(
  _ lease: VendorCharonControlLease,
  factory: CharonControlDriverFactory
) async -> VendorCharonControlReceipt {
  let task = Task { await lease.stop(timeoutMilliseconds: 500) }
  #expect(await waitForControl { factory.driver.submitCount == 2 })
  factory.driver.emitReply(.emptyAcknowledgement, at: 1)
  return await task.value
}

private func diagnosticTunnelNameObject(nameKey: String?) -> xpc_object_t {
  let object = xpc_dictionary_create(nil, nil, 0)
  xpc_dictionary_set_bool(object, "get_tun_name_success", true)
  if let nameKey {
    xpc_dictionary_set_string(object, nameKey, "utun-value-must-not-escape")
  }
  return object
}

private func diagnosticStatusObject(name: String) -> xpc_object_t {
  let object = xpc_dictionary_create(nil, nil, 0)
  xpc_dictionary_set_string(object, "name", name)
  xpc_dictionary_set_int64(object, "type", 1)
  xpc_dictionary_set_int64(object, "phase", 2)
  xpc_dictionary_set_int64(object, "state", 5)
  return object
}
