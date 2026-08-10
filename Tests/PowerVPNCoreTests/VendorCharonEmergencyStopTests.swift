import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonEmergencyStopTests {
  @Test func blockedPreflightCreatesNoDriverAndSendsNothing() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = EmergencyStopGate(factory: factory, result: false)

    let receipt = await emergencyTransport(factory).emergencyStop(
      timeoutMilliseconds: 500,
      expectedRunningPredicate: gate.evaluate,
      peerGenerationValidator: { _ in true }
    )

    #expect(gate.callCount == 1)
    #expect(gate.factoryCallsObserved == [0])
    #expect(receipt.outcome == .preflightBlocked)
    #expect(!receipt.requestSent)
    #expect(!receipt.connectionCancelRequested)
    #expect(factory.callCount == 0)
    #expect(factory.driver.observations.isEmpty)
  }

  @Test func exactProbeAuthenticatesBeforeStopOnTheSameConnection() async {
    let factory = EmergencyConnectionDriverFactory()
    let gate = EmergencyStopGate(factory: factory, result: true)
    let task = emergencyStopTask(
      factory,
      gate: gate.evaluate,
      peerGenerationValidator: { $0 == 41 }
    )
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    #expect(gate.factoryCallsObserved == [0])
    #expect(factory.driver.observations == [.getVersion])
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness(peerPID: 41)
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    #expect(factory.callCount == 1)
    #expect(factory.driver.observations == [.getVersion, .stopConnection])
    factory.driver.emitStopEvent(
      .status(VendorCharonStatusSignal(type: 1, phase: 2, state: 7))
    )
    factory.driver.emitStopReply(.emptyAcknowledgement(peerPID: 41))
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(receipt.statusEventCount == 1)
    #expect(receipt.connectionCancelRequested)
    #expect(!receipt.cleanupEstablished)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func businessFirstStillWaitsForEmptyProbeReplyBeforeStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory)
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeBusiness(peerPID: 1)
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    factory.driver.emitStopReply(.emptyAcknowledgement(peerPID: 1))

    let receipt = await task.value
    #expect(receipt.transportAcknowledged)
    #expect(factory.driver.observations == [.getVersion, .stopConnection])
  }

  @Test func peerMismatchNeverSendsStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { $0 == 7 })
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeBusiness(peerPID: 8)
    let receipt = await task.value

    #expect(receipt.outcome == .peerGenerationMismatch)
    #expect(!receipt.requestSent)
    #expect(!receipt.peerGenerationValidated)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func stopReplyFromDifferentPeerCannotAcknowledgeCleanup() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { $0 == 41 })
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness(peerPID: 41)
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    factory.driver.emitStopReply(.emptyAcknowledgement(peerPID: 42))
    let receipt = await task.value

    #expect(receipt.outcome == .peerGenerationMismatch)
    #expect(receipt.requestSent)
    #expect(receipt.emptyReplyObserved)
    #expect(!receipt.peerGenerationValidated)
    #expect(!receipt.transportAcknowledged)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func peerDriftBeforeStopSubmissionSendsNoStop() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory, peerGenerationValidator: { $0 == 41 })
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeBusiness(peerPID: 41)
    factory.driver.setCurrentPeerPID(42)
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    let receipt = await task.value

    #expect(receipt.outcome == .peerGenerationMismatch)
    #expect(!receipt.requestSent)
    #expect(!receipt.peerGenerationValidated)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func versionAndProbeErrorsNeverSendStop() async {
    let cases: [(VendorXPCConnectionEvent, VendorCharonControlOutcome)] = [
      (
        .business(
          VendorXPCBusinessReply(
            versionByteLength: 5,
            versionMatchesLockedBuild: false,
            getVersionSuccess: true
          ),
          peerPID: 1
        ),
        .helperVersionMismatch
      ),
      (
        .business(
          VendorXPCBusinessReply(
            versionByteLength: 5,
            versionMatchesLockedBuild: true,
            getVersionSuccess: false
          ),
          peerPID: 1
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
      (.connectionInterrupted, .connectionInterrupted),
      (.connectionInvalid, .connectionInvalid),
      (.peerCodeSigningRequirement, .peerCodeSigningRequirement),
      (.unexpectedXPCError, .unexpectedXPCError),
      (.unexpectedPayload, .unexpectedReplyPayload),
    ]
    for (event, expected) in replyCases {
      let factory = EmergencyConnectionDriverFactory()
      let task = emergencyStopTask(factory)
      #expect(await waitForControl { factory.driver.probeCount == 1 })
      factory.driver.emitProbeBusiness(peerPID: 1)
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
    let receipt = await emergencyTransport(factory).emergencyStop(
      timeoutMilliseconds: 5,
      expectedRunningPredicate: { true },
      peerGenerationValidator: { _ in true }
    )

    #expect(receipt.outcome == .timeout)
    #expect(!receipt.requestSent)
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitProbeBusiness(peerPID: 1)
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func missingEitherProbeEvidenceTimesOutWithoutStop() async {
    for businessPresent in [true, false] {
      let factory = EmergencyConnectionDriverFactory()
      let task = Task {
        await emergencyTransport(factory).emergencyStop(
          timeoutMilliseconds: 5,
          expectedRunningPredicate: { true },
          peerGenerationValidator: { _ in true }
        )
      }
      #expect(await waitForControl { factory.driver.probeCount == 1 })
      if businessPresent {
        factory.driver.emitProbeBusiness(peerPID: 1)
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
    factory.driver.emitProbeBusiness(peerPID: 1)
    await Task.yield()
    #expect(factory.driver.stopCount == 0)
  }

  @Test func cancellationAfterStopSubmissionIsTruthfulAndLateReplyIsIgnored() async {
    let factory = EmergencyConnectionDriverFactory()
    let task = emergencyStopTask(factory)
    #expect(await waitForControl { factory.driver.probeCount == 1 })
    factory.driver.emitProbeReply(.emptyAcknowledgement)
    factory.driver.emitProbeBusiness(peerPID: 1)
    #expect(await waitForControl { factory.driver.stopCount == 1 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(receipt.requestSent)
    #expect(receipt.peerGenerationValidated)
    #expect(factory.driver.cancelCount == 1)
    factory.driver.emitStopReply(.emptyAcknowledgement(peerPID: 1))
    await Task.yield()
    #expect(factory.driver.stopCount == 1)
    #expect(factory.driver.cancelCount == 1)
  }

}
