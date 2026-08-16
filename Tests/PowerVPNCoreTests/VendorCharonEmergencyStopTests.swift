import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonEmergencyStopTests {
  @Test func blockedPreflightCreatesNoDriverAndSendsNothing() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = EmergencyStopGate(factory: factory, result: false)

    let receipt = await emergencyTransport(factory).emergencyStop(
      timeoutMilliseconds: 500,
      stopContext: syntheticEmergencyStopContext,
      expectedRunningPredicate: gate.evaluate,
      peerGenerationValidator: { true }
    )

    #expect(gate.callCount == 1)
    #expect(gate.factoryCallsObserved == [0])
    #expect(receipt.outcome == .preflightBlocked)
    #expect(!receipt.requestSent)
    #expect(!receipt.connectionCancelRequested)
    #expect(factory.callCount == 0)
    #expect(factory.driver.observations.isEmpty)
  }

  @Test func exactProbeAuthenticatesBeforeStopOnTheSameSession() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = EmergencyStopGate(factory: factory, result: true)
    let scheduler = ManualConnectionDrainScheduler()
    let task = emergencyStopTask(
      factory,
      gate: gate.evaluate,
      peerGenerationValidator: { true },
      drainScheduler: scheduler.schedule
    )
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    #expect(gate.factoryCallsObserved == [0])
    #expect(factory.driver.observations == [.getVersion])
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    #expect(factory.callCount == 1)
    #expect(
      factory.driver.observations == [
        .getVersion,
        .stopConnection(gateway: "synthetic-gateway"),
      ])
    factory.driver.emitStopEvent(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 7))
    )
    factory.driver.emitStopEvent(.tunnelNameReported(success: true))
    factory.driver.emitStopReply(.emptyAcknowledgement)
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(receipt.statusEventCount == 1)
    #expect(!receipt.connectionCancelRequested)
    #expect(!receipt.cleanupEstablished)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func disconnectedStatusAcknowledgesSubmittedEmergencyStopWithoutReply() async {
    let factory = EmergencyConnectionDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let task = emergencyStopTask(
      factory,
      peerGenerationValidator: { true },
      drainScheduler: scheduler.schedule
    )
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })

    factory.driver.emitStopEvent(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 7))
    )
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.completionSource == .ordinaryConnection)
    #expect(receipt.statusEventCount == 1)
    #expect(!receipt.emptyReplyObserved)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func connectionTailAcknowledgesStopWithoutReplyAndArmsDrain() async {
    let factory = EmergencyConnectionDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let task = emergencyStopTask(
      factory,
      peerGenerationValidator: { true },
      drainScheduler: scheduler.schedule
    )
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })

    factory.driver.emitStopEvent(.emptyDispatcherTail)
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.emptyReplyObserved)
    #expect(receipt.peerGenerationValidated)
    #expect(receipt.dispatcherTailEventCount == 1)
    #expect(!receipt.connectionRetained)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)

    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func replyUnavailableProbeAndStopContinueOnOrdinaryConnectionEvents() async {
    let factory = EmergencyConnectionDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let task = emergencyStopTask(
      factory,
      peerGenerationValidator: { true },
      drainScheduler: scheduler.schedule
    )
    #expect(await waitForControl { factory.driver.probeCount == 1 })

    factory.driver.emitProbeReply(.replyUnavailable)
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 0)

    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    factory.driver.emitStopReply(.replyUnavailable)
    await Task.yield()
    #expect(factory.driver.cancelCount == 0)

    factory.driver.emitStopEvent(.emptyDispatcherTail)
    let receipt = await task.value
    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(receipt.dispatcherTailEventCount == 1)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
  }

  @Test func businessFirstStillWaitsForEmptyProbeReplyBeforeStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory)
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeBusiness()
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    factory.driver.emitStopReply(.emptyAcknowledgement)

    let receipt = await task.value
    #expect(receipt.transportAcknowledged)
    #expect(
      factory.driver.observations == [
        .getVersion,
        .stopConnection(gateway: "synthetic-gateway"),
      ])
  }

  @Test func generationMismatchNeverSendsStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { false })
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeBusiness()
    let receipt = await task.value

    #expect(receipt.outcome == .peerGenerationMismatch)
    #expect(!receipt.requestSent)
    #expect(!receipt.peerGenerationValidated)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func sessionInvalidationAfterStopSubmissionCannotAcknowledge() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { true })
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    factory.driver.invalidateSession()
    factory.driver.emitStopEvent(.connectionInvalid)
    let receipt = await task.value

    #expect(receipt.outcome == .connectionInvalid)
    #expect(receipt.requestSent)
    #expect(!receipt.emptyReplyObserved)
    #expect(receipt.peerGenerationValidated)
    #expect(!receipt.transportAcknowledged)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func invalidatedSessionCannotSubmitStopAfterProbeCompletes() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { true })
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeBusiness()
    factory.driver.invalidateSession()
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    let receipt = await task.value

    #expect(receipt.outcome == .connectionInvalid)
    #expect(!receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func versionAndProbeErrorsNeverSendStop() async {
    let cases: [(VendorCharonEmergencyProbeEvent, VendorCharonControlOutcome)] = [
      (
        .business(
          VendorXPCBusinessReply(
            versionByteLength: 5,
            versionMatchesLockedBuild: false,
            getVersionSuccess: true
          )
        ),
        .helperVersionMismatch
      ),
      (
        .business(
          VendorXPCBusinessReply(
            versionByteLength: 5,
            versionMatchesLockedBuild: true,
            getVersionSuccess: false
          )
        ),
        .helperVersionRejected
      ),
      (.malformedBusinessEvent, .unexpectedConnectionEvent),
      (.connectionInterrupted, .connectionInterrupted),
    ]

    for (event, expected) in cases {
      let factory = EmergencyConnectionDriverFactory()
      let task = emergencyStopTask(factory)
      #expect(await waitForControl { factory.driver.probeCount == 1 })
      factory.driver.emitProbe(event)
      let receipt = await task.value
      #expect(receipt.outcome == expected)
      #expect(!receipt.requestSent)
      #expect(factory.driver.stopCount == 0)
      #expect(factory.driver.cancelCount == 1)
    }
  }

  @Test func probeReplyErrorAfterValidBusinessNeverSendsStop() async {
    let replyCases: [(VendorXPCReplyCallbackEvent, VendorCharonControlOutcome)] = [
      (.peerCodeSigningRequirement, .peerCodeSigningRequirement),
      (.unexpectedXPCError, .unexpectedXPCError),
      (.unexpectedPayload, .unexpectedReplyPayload),
    ]
    for (event, expected) in replyCases {
      let factory = EmergencyConnectionDriverFactory()
      let task = emergencyStopTask(factory)
      #expect(await waitForControl { factory.driver.probeCount == 1 })
      factory.driver.emitProbeBusiness()
      factory.driver.emitProbeReply(event)
      let receipt = await task.value
      #expect(receipt.outcome == expected)
      #expect(!receipt.requestSent)
      #expect(factory.driver.stopCount == 0)
      #expect(factory.driver.cancelCount == 1)
    }
  }

  @Test func probeTimeoutCancelsOnceAndNeverSendsStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = Task {
      await emergencyTransport(factory).emergencyStop(
        timeoutMilliseconds: 100,
        stopContext: syntheticEmergencyStopContext,
        expectedRunningPredicate: { true },
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    let receipt = await task.value

    #expect(receipt.outcome == .timeout)
    #expect(!receipt.requestSent)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitProbeBusiness()
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func missingEitherProbeEvidenceTimesOutWithoutStop() async {
    for businessPresent in [true, false] {
      let factory = EmergencyConnectionDriverFactory()
      let task = Task {
        await emergencyTransport(factory).emergencyStop(
          timeoutMilliseconds: 100,
          stopContext: syntheticEmergencyStopContext,
          expectedRunningPredicate: { true },
          peerGenerationValidator: { true }
        )
      }
      #expect(await waitForControl { factory.driver.probeCount == 1 })
      if businessPresent {
        factory.driver.emitProbeBusiness()
      } else {
        factory.driver.emitProbeReply(.emptyAcknowledgement)
      }
      let receipt = await task.value
      #expect(receipt.outcome == .timeout)
      #expect(!receipt.requestSent)
      #expect(factory.driver.stopCount == 0)
      #expect(factory.driver.cancelCount == 1)
    }
  }

  @Test func submittedEmergencyStopTimeoutTransfersDriverToDrain() async {
    let factory = EmergencyConnectionDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let task = emergencyStopTask(
      factory,
      timeoutMilliseconds: 100,
      drainScheduler: scheduler.schedule
    )
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })

    let receipt = await task.value

    #expect(receipt.outcome == .timeout)
    #expect(receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(!receipt.emptyReplyObserved)
    #expect(!receipt.transportAcknowledged)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func cancellationDuringProbeNeverSendsStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory)
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(!receipt.requestSent)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitProbeBusiness()
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
  }

  @Test func emergencyCancellationAfterStopSubmissionTransfersDriverToDrain() async {
    let factory = EmergencyConnectionDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let task = emergencyStopTask(factory, drainScheduler: scheduler.schedule)
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(!receipt.connectionCancelRequested)
    #expect(scheduler.isArmed)
    #expect(factory.driver.cancelCount == 0)
    factory.driver.emitStopReply(.emptyAcknowledgement)
    await Task.yield()
    #expect(factory.driver.stopCount == 1)
    #expect(factory.driver.cancelCount == 0)
    scheduler.expire()
    #expect(await waitForControl { factory.driver.cancelCount == 1 })
  }

  @Test func emergencyPostStopDrainWaitCompletesOnlyAfterExpiry() async {
    let factory = EmergencyConnectionDriverFactory()
    let scheduler = ManualConnectionDrainScheduler()
    let resultTask = Task {
      await emergencyTransport(factory).emergencyStopWithDrain(
        timeoutMilliseconds: 500,
        stopContext: syntheticEmergencyStopContext,
        expectedRunningPredicate: { true },
        peerGenerationValidator: { true },
        postStopDrainScheduler: scheduler.schedule
      )
    }
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness()
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    factory.driver.emitStopReply(.emptyAcknowledgement)
    let result = await resultTask.value
    #expect(result.receipt.outcome == .transportAcknowledged)

    let completion = DrainCompletionProbe()
    let waiter = Task {
      await result.awaitPostStopDrain()
      completion.mark()
    }
    waiter.cancel()
    await Task.yield()
    #expect(!completion.isComplete)
    scheduler.expire()
    await waiter.value
    #expect(completion.isComplete)
    #expect(factory.driver.cancelCount == 1)
  }

}
