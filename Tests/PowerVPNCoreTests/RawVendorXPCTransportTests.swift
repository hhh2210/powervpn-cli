import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct RawVendorXPCTransportTests {
  @Test func validatesBusinessPeerAndRecordsTransportTailsDuringHold() async {
    #expect(RawVendorXPCTransport.businessObservationHoldMilliseconds == 200)
    let reply = acceptedReply()
    let driver = ScriptedVendorXPCDriver(steps: [
      .connection(.business(reply, peerPID: 4321)),
      .connection(.emptyDispatcherTail),
      .reply(.emptyAcknowledgement),
    ])

    let evidence = await transport(driver).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { $0 == 4321 }
    )

    #expect(evidence.accepted)
    #expect(evidence.versionByteLength == 5)
    #expect(evidence.versionMatchesLockedBuild)
    #expect(evidence.getVersionSuccess)
    #expect(evidence.replyPeerGenerationValidated)
    #expect(evidence.emptyDispatcherTailObserved)
    #expect(evidence.emptyReplyAcknowledgementObserved)
    #expect(evidence.connectionCancelRequested)
    #expect(driver.cancelCount == 1)

    let unbound = await transport(
      ScriptedVendorXPCDriver(steps: [
        .connection(.business(acceptedReply(), peerPID: 9))
      ])
    ).getVersion(timeoutMilliseconds: 500, peerGenerationValidator: { _ in false })
    #expect(unbound.outcome == .accepted)
    #expect(!unbound.replyPeerGenerationValidated)
    #expect(!unbound.accepted)
  }

  @Test func ignoresEmptyTransportSignalsUntilBusinessEvent() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .reply(.emptyAcknowledgement),
      .connection(.emptyDispatcherTail),
      .connection(.business(acceptedReply(), peerPID: 72)),
    ])

    let evidence = await transport(driver).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { $0 == 72 }
    )

    #expect(evidence.accepted)
    #expect(evidence.emptyReplyAcknowledgementObserved)
    #expect(evidence.emptyDispatcherTailObserved)
    #expect(evidence.replyPeerGenerationValidated)
    #expect(driver.cancelCount == 1)
  }

  @Test func fullReplyCallbackCanNeverProveAcceptance() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .reply(.unexpectedPayload),
      .connection(.business(acceptedReply(), peerPID: 4)),
    ])

    let evidence = await transport(driver).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { _ in true }
    )

    #expect(evidence.outcome == .unexpectedReplyPayload)
    #expect(!evidence.accepted)
    #expect(!evidence.replyPeerGenerationValidated)
    #expect(driver.cancelCount == 1)
  }

  @Test func replyUnavailableThenOrdinaryBusinessStillAuthenticates() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .reply(.replyUnavailable),
      .connection(.business(acceptedReply(), peerPID: 4)),
    ])

    let evidence = await transport(driver).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { $0 == 4 }
    )

    #expect(evidence.outcome == .accepted)
    #expect(evidence.accepted)
    #expect(evidence.replyPeerGenerationValidated)
    #expect(driver.cancelCount == 1)
  }

  @Test func classifiesErrorsFromBothDriverChannels() async {
    let cases: [(DriverStep, VendorXPCGetVersionOutcome)] = [
      (.connection(.connectionInterrupted), .connectionInterrupted),
      (.connection(.connectionInvalid), .connectionInvalid),
      (.connection(.peerCodeSigningRequirement), .peerCodeSigningRequirement),
      (.reply(.peerCodeSigningRequirement), .peerCodeSigningRequirement),
      (.connection(.unexpectedXPCError), .unexpectedXPCError),
      (.reply(.unexpectedXPCError), .unexpectedXPCError),
      (.connection(.malformedBusinessEvent), .malformedBusinessEvent),
      (.connection(.unexpectedConnectionEvent), .unexpectedConnectionEvent),
    ]

    for (step, expected) in cases {
      let driver = ScriptedVendorXPCDriver(steps: [step])
      let evidence = await transport(driver).getVersion(
        timeoutMilliseconds: 500,
        peerGenerationValidator: { _ in true }
      )
      #expect(evidence.outcome == expected)
      #expect(!evidence.accepted)
      #expect(!evidence.replyPeerGenerationValidated)
      #expect(driver.cancelCount == 1)
    }
  }

  @Test func classifiesLockedVersionMismatchAndNegativeFlagSeparately() async {
    let mismatch = ScriptedVendorXPCDriver(steps: [
      .connection(
        .business(
          VendorXPCBusinessReply(
            versionByteLength: 5,
            versionMatchesLockedBuild: false,
            getVersionSuccess: true
          ),
          peerPID: 5
        ))
    ])
    let negative = ScriptedVendorXPCDriver(steps: [
      .connection(
        .business(
          VendorXPCBusinessReply(
            versionByteLength: 5,
            versionMatchesLockedBuild: true,
            getVersionSuccess: false
          ),
          peerPID: 6
        ))
    ])

    let mismatchEvidence = await transport(mismatch).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { $0 == 5 }
    )
    let negativeEvidence = await transport(negative).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { $0 == 6 }
    )

    #expect(mismatchEvidence.outcome == .lockedVersionMismatch)
    #expect(mismatchEvidence.versionByteLength == 5)
    #expect(!mismatchEvidence.versionMatchesLockedBuild)
    #expect(mismatchEvidence.replyPeerGenerationValidated)
    #expect(negativeEvidence.outcome == .getVersionRejected)
    #expect(negativeEvidence.versionMatchesLockedBuild)
    #expect(!negativeEvidence.getVersionSuccess)
    #expect(negativeEvidence.replyPeerGenerationValidated)
  }

  @Test func timeoutWinsOnceAndLateInvalidationCannotOverwriteIt() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .reply(.emptyAcknowledgement),
      .connection(.emptyDispatcherTail),
    ])

    let evidence = await transport(driver).getVersion(
      timeoutMilliseconds: 10,
      peerGenerationValidator: { _ in true }
    )
    driver.emitConnection(.connectionInvalid)
    await Task.yield()

    #expect(evidence.outcome == .timeout)
    #expect(evidence.emptyReplyAcknowledgementObserved)
    #expect(evidence.emptyDispatcherTailObserved)
    #expect(evidence.connectionCancelRequested)
    #expect(driver.cancelCount == 1)
  }

  @Test func acceptedBusinessWinsOverLateInterruptionAndCancelsOnce() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .connection(.business(acceptedReply(), peerPID: 8)),
      .connection(.connectionInterrupted),
    ])
    let evidence = await transport(driver, holdMilliseconds: 20).getVersion(
      timeoutMilliseconds: 500,
      peerGenerationValidator: { $0 == 8 }
    )
    try? await Task.sleep(for: .milliseconds(30))

    #expect(evidence.outcome == .accepted)
    #expect(evidence.accepted)
    #expect(driver.cancelCount == 1)
  }

  @Test func acceptedBusinessWinsOverTimeoutDuringObservationHold() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .connection(.business(acceptedReply(), peerPID: 8))
    ])
    let evidence = await transport(driver, holdMilliseconds: 20).getVersion(
      timeoutMilliseconds: 1,
      peerGenerationValidator: { $0 == 8 }
    )
    try? await Task.sleep(for: .milliseconds(30))

    #expect(evidence.outcome == .accepted)
    #expect(evidence.replyPeerGenerationValidated)
    #expect(driver.cancelCount == 1)
  }

  @Test func invalidTimeoutDoesNotCreateOrCancelADriver() async {
    let driver = ScriptedVendorXPCDriver(steps: [])
    let validator = PeerValidatorRecorder()
    let evidence = await transport(driver).getVersion(
      timeoutMilliseconds: 0,
      peerGenerationValidator: { validator.validate($0, expected: 1) }
    )

    #expect(evidence.outcome == .invalidTimeout)
    #expect(!evidence.connectionCancelRequested)
    #expect(driver.startCount == 0)
    #expect(driver.cancelCount == 0)
    #expect(validator.callCount == 0)
  }

  @Test func taskCancellationCancelsAnActiveConnectionExactlyOnce() async {
    let driver = ScriptedVendorXPCDriver(steps: [])
    let task = Task {
      await transport(driver).getVersion(
        timeoutMilliseconds: 500,
        peerGenerationValidator: { _ in true }
      )
    }
    for _ in 0..<100 where driver.startCount == 0 {
      await Task.yield()
    }
    #expect(driver.startCount == 1)

    task.cancel()
    let evidence = await task.value

    #expect(evidence.outcome == .cancelled)
    #expect(evidence.connectionCancelRequested)
    #expect(driver.cancelCount == 1)
  }

  @Test func timeoutBoundsAnAsyncPeerGenerationValidation() async {
    let driver = ScriptedVendorXPCDriver(steps: [
      .connection(.business(acceptedReply(), peerPID: 44))
    ])

    let evidence = await transport(
      driver,
      validationTimeoutMilliseconds: 10
    ).getVersion(
      timeoutMilliseconds: 10,
      peerGenerationValidator: { _ in
        try? await Task.sleep(for: .seconds(5))
        return true
      }
    )

    #expect(evidence.outcome == .timeout)
    #expect(!evidence.accepted)
    #expect(evidence.connectionCancelRequested)
    #expect(driver.cancelCount == 1)
  }
}

private enum DriverStep: Sendable {
  case connection(VendorXPCConnectionEvent)
  case reply(VendorXPCReplyCallbackEvent)
}

private final class ScriptedVendorXPCDriver: @unchecked Sendable,
  VendorXPCConnectionDriving
{
  private let lock = NSLock()
  private let steps: [DriverStep]
  private var connectionHandler: (@Sendable (VendorXPCConnectionEvent) -> Void)?
  private var replyHandler: (@Sendable (VendorXPCReplyCallbackEvent) -> Void)?
  private var starts = 0
  private var cancels = 0

  init(steps: [DriverStep]) {
    self.steps = steps
  }

  var startCount: Int { locked { starts } }
  var cancelCount: Int { locked { cancels } }

  func start(
    connectionEventHandler: @escaping @Sendable (VendorXPCConnectionEvent) -> Void,
    replyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void
  ) {
    locked {
      starts += 1
      connectionHandler = connectionEventHandler
      self.replyHandler = replyHandler
    }
    for step in steps {
      switch step {
      case .connection(let event): connectionEventHandler(event)
      case .reply(let event): replyHandler(event)
      }
    }
  }

  func cancel() {
    locked { cancels += 1 }
  }

  func emitConnection(_ event: VendorXPCConnectionEvent) {
    let handler = locked { connectionHandler }
    handler?(event)
  }

  private func locked<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

private func transport(
  _ driver: ScriptedVendorXPCDriver,
  holdMilliseconds: Int = 5,
  validationTimeoutMilliseconds: Int =
    RawVendorXPCTransport.peerGenerationValidationTimeoutMilliseconds
) -> RawVendorXPCTransport {
  RawVendorXPCTransport(
    driverFactory: { _ in driver },
    businessObservationHoldMilliseconds: holdMilliseconds,
    peerGenerationValidationTimeoutMilliseconds: validationTimeoutMilliseconds
  )
}

private func acceptedReply() -> VendorXPCBusinessReply {
  VendorXPCBusinessReply(
    versionByteLength: 5,
    versionMatchesLockedBuild: true,
    getVersionSuccess: true
  )
}

private final class PeerValidatorRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0

  var callCount: Int {
    lock.withLock { calls }
  }

  func validate(_ peerPID: Int32, expected: Int32) -> Bool {
    lock.withLock { calls += 1 }
    return peerPID == expected
  }
}
