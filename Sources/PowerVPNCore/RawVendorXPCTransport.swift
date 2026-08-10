import Dispatch
import Foundation
@preconcurrency import XPC

public struct RawVendorXPCTransport: VendorXPCTransporting, Sendable {
  public static let defaultTimeoutMilliseconds = 2_000
  public static let validTimeoutMilliseconds = 1...60_000
  public static let businessObservationHoldMilliseconds = 200
  static let peerGenerationValidationTimeoutMilliseconds = 2_000

  private let driverFactory: @Sendable (DispatchQueue) -> any VendorXPCConnectionDriving
  private let businessObservationHoldMilliseconds: Int
  private let peerGenerationValidationTimeoutMilliseconds: Int

  public init() {
    driverFactory = { SystemVendorXPCConnectionDriver(queue: $0) }
    businessObservationHoldMilliseconds = Self.businessObservationHoldMilliseconds
    peerGenerationValidationTimeoutMilliseconds =
      Self.peerGenerationValidationTimeoutMilliseconds
  }

  init(
    driverFactory: @escaping @Sendable (DispatchQueue) -> any VendorXPCConnectionDriving,
    businessObservationHoldMilliseconds: Int = Self.businessObservationHoldMilliseconds,
    peerGenerationValidationTimeoutMilliseconds: Int =
      Self.peerGenerationValidationTimeoutMilliseconds
  ) {
    self.driverFactory = driverFactory
    self.businessObservationHoldMilliseconds = businessObservationHoldMilliseconds
    self.peerGenerationValidationTimeoutMilliseconds =
      peerGenerationValidationTimeoutMilliseconds
  }

  public func getVersion(
    timeoutMilliseconds: Int = Self.defaultTimeoutMilliseconds,
    peerGenerationValidator: @escaping @Sendable (Int32) async -> Bool
  ) async -> VendorXPCGetVersionEvidence {
    guard Self.validTimeoutMilliseconds.contains(timeoutMilliseconds) else {
      return VendorXPCGetVersionEvidence(
        outcome: .invalidTimeout,
        connectionCancelRequested: false
      )
    }
    guard !Task.isCancelled else {
      return VendorXPCGetVersionEvidence(
        outcome: .cancelled,
        connectionCancelRequested: false
      )
    }
    let queue = DispatchQueue(label: "com.powervpn.r1.raw-xpc")
    let attempt = VendorXPCGetVersionAttempt()
    let transaction = VendorXPCGetVersionTransaction(
      queue: queue,
      driver: driverFactory(queue),
      timeoutMilliseconds: timeoutMilliseconds,
      businessObservationHoldMilliseconds: businessObservationHoldMilliseconds,
      peerGenerationValidationTimeoutMilliseconds:
        peerGenerationValidationTimeoutMilliseconds,
      peerGenerationValidator: peerGenerationValidator
    )
    return await withTaskCancellationHandler {
      await transaction.run(attempt: attempt)
    } onCancel: {
      attempt.cancel()
      transaction.cancel(attempt: attempt)
    }
  }
}

private final class VendorXPCGetVersionAttempt: @unchecked Sendable {
  private let lock = NSLock()
  private var cancelled = false

  var isCancelled: Bool { lock.withLock { cancelled } }

  func cancel() {
    lock.withLock { cancelled = true }
  }
}

private final class SystemVendorXPCConnectionDriver: @unchecked Sendable,
  VendorXPCConnectionDriving
{
  private static let serviceName = VendorXPCSessionContract.serviceName

  private let connection: xpc_connection_t
  private let queue: DispatchQueue
  private var cancelled = false

  init(queue: DispatchQueue) {
    self.queue = queue
    connection = Self.serviceName.withCString { service in
      xpc_connection_create_mach_service(
        service,
        queue,
        UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED)
      )
    }
  }

  func start(
    connectionEventHandler: @escaping @Sendable (VendorXPCConnectionEvent) -> Void,
    replyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void
  ) {
    xpc_connection_set_event_handler(connection) { [self] object in
      connectionEventHandler(
        VendorXPCWireCodec.connectionEvent(
          object,
          peerPID: xpc_connection_get_pid(connection)
        ))
    }
    xpc_connection_activate(connection)
    xpc_connection_send_message_with_reply(
      connection,
      VendorXPCWireCodec.makeGetVersionRequest(),
      queue
    ) { object in
      replyHandler(VendorXPCWireCodec.replyCallback(object))
    }
  }

  func cancel() {
    guard !cancelled else { return }
    cancelled = true
    xpc_connection_set_event_handler(connection) { _ in }
    xpc_connection_cancel(connection)
  }
}

private final class VendorXPCGetVersionTransaction: @unchecked Sendable {
  private let queue: DispatchQueue
  private var driver: (any VendorXPCConnectionDriving)?
  private let timeoutMilliseconds: Int
  private let businessObservationHoldMilliseconds: Int
  private let peerGenerationValidationTimeoutMilliseconds: Int
  private let peerGenerationValidator: @Sendable (Int32) async -> Bool
  private var continuation: CheckedContinuation<VendorXPCGetVersionEvidence, Never>?
  private var timer: DispatchSourceTimer?
  private var peerValidationTask: Task<Void, Never>?
  private var currentAttempt: VendorXPCGetVersionAttempt?
  private var finished = false
  private var businessOutcomePending = false
  private var businessValidationPending = false
  private var emptyDispatcherTailObserved = false
  private var emptyReplyAcknowledgementObserved = false

  init(
    queue: DispatchQueue,
    driver: any VendorXPCConnectionDriving,
    timeoutMilliseconds: Int,
    businessObservationHoldMilliseconds: Int,
    peerGenerationValidationTimeoutMilliseconds: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) async -> Bool
  ) {
    self.queue = queue
    self.driver = driver
    self.timeoutMilliseconds = timeoutMilliseconds
    self.businessObservationHoldMilliseconds = businessObservationHoldMilliseconds
    self.peerGenerationValidationTimeoutMilliseconds =
      peerGenerationValidationTimeoutMilliseconds
    self.peerGenerationValidator = peerGenerationValidator
  }

  func run(attempt: VendorXPCGetVersionAttempt) async -> VendorXPCGetVersionEvidence {
    await withCheckedContinuation { continuation in
      queue.async { [self] in
        guard !attempt.isCancelled else {
          continuation.resume(
            returning: VendorXPCGetVersionEvidence(
              outcome: .cancelled,
              connectionCancelRequested: false
            ))
          return
        }
        self.continuation = continuation
        currentAttempt = attempt
        armTimeout()
        driver?.start(
          connectionEventHandler: { [self] event in
            queue.async { [self] in handle(event) }
          },
          replyHandler: { [self] event in
            queue.async { [self] in handle(event) }
          }
        )
      }
    }
  }

  func cancel(attempt: VendorXPCGetVersionAttempt) {
    queue.async { [self] in
      guard currentAttempt === attempt, !finished else { return }
      finish(outcome: .cancelled)
    }
  }

  private func armTimeout() {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    let deadline = DispatchTime.now() + .milliseconds(timeoutMilliseconds)
    timer.schedule(deadline: deadline)
    timer.setEventHandler { [self] in finishFailure(.timeout) }
    self.timer = timer
    timer.resume()
  }

  private func handle(_ event: VendorXPCConnectionEvent) {
    guard !finished else { return }
    switch event {
    case .business(let reply, let peerPID):
      guard !businessOutcomePending else { return }
      let outcome: VendorXPCGetVersionOutcome
      if !reply.versionMatchesLockedBuild {
        outcome = .lockedVersionMismatch
      } else if !reply.getVersionSuccess {
        outcome = .getVersionRejected
      } else {
        outcome = .accepted
      }
      businessOutcomePending = true
      businessValidationPending = true
      timer?.cancel()
      timer = nil
      armPeerValidationTimeout()
      peerValidationTask = Task { [self] in
        let peerGenerationValidated = await peerGenerationValidator(peerPID)
        queue.async { [self] in
          guard !finished, businessValidationPending else { return }
          businessValidationPending = false
          holdBusinessOutcome(
            outcome,
            reply: reply,
            replyPeerGenerationValidated: peerGenerationValidated
          )
        }
      }
    case .emptyDispatcherTail:
      emptyDispatcherTailObserved = true
    case .malformedBusinessEvent:
      holdBusinessOutcome(.malformedBusinessEvent)
    case .connectionInterrupted:
      finishFailure(.connectionInterrupted)
    case .connectionInvalid:
      finishFailure(.connectionInvalid)
    case .peerCodeSigningRequirement:
      finishFailure(.peerCodeSigningRequirement)
    case .unexpectedXPCError:
      finishFailure(.unexpectedXPCError)
    case .unexpectedConnectionEvent:
      finishFailure(.unexpectedConnectionEvent)
    }
  }

  private func armPeerValidationTimeout() {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(
      deadline: .now() + .milliseconds(peerGenerationValidationTimeoutMilliseconds)
    )
    timer.setEventHandler { [self] in finish(outcome: .timeout) }
    self.timer = timer
    timer.resume()
  }

  private func handle(_ event: VendorXPCReplyCallbackEvent) {
    guard !finished else { return }
    switch event {
    case .emptyAcknowledgement:
      emptyReplyAcknowledgementObserved = true
    case .connectionInterrupted:
      finishFailure(.connectionInterrupted)
    case .connectionInvalid:
      finishFailure(.connectionInvalid)
    case .peerCodeSigningRequirement:
      finishFailure(.peerCodeSigningRequirement)
    case .unexpectedXPCError:
      finishFailure(.unexpectedXPCError)
    case .unexpectedPayload:
      finishFailure(.unexpectedReplyPayload)
    }
  }

  private func holdBusinessOutcome(
    _ outcome: VendorXPCGetVersionOutcome,
    reply: VendorXPCBusinessReply? = nil,
    replyPeerGenerationValidated: Bool = false
  ) {
    guard !finished, !businessValidationPending else { return }
    businessOutcomePending = true
    timer?.cancel()
    timer = nil
    queue.asyncAfter(
      deadline: .now() + .milliseconds(businessObservationHoldMilliseconds)
    ) { [self] in
      finish(
        outcome: outcome,
        reply: reply,
        replyPeerGenerationValidated: replyPeerGenerationValidated
      )
    }
  }

  private func finishFailure(_ outcome: VendorXPCGetVersionOutcome) {
    guard !businessOutcomePending else { return }
    finish(outcome: outcome)
  }

  private func finish(
    outcome: VendorXPCGetVersionOutcome,
    reply: VendorXPCBusinessReply? = nil,
    replyPeerGenerationValidated: Bool = false
  ) {
    guard !finished else { return }
    finished = true
    timer?.cancel()
    timer = nil
    peerValidationTask?.cancel()
    peerValidationTask = nil
    currentAttempt = nil
    let currentDriver = driver
    driver = nil
    currentDriver?.cancel()
    let result = VendorXPCGetVersionEvidence(
      outcome: outcome,
      versionByteLength: reply?.versionByteLength,
      versionMatchesLockedBuild: reply?.versionMatchesLockedBuild ?? false,
      getVersionSuccess: reply?.getVersionSuccess ?? false,
      emptyDispatcherTailObserved: emptyDispatcherTailObserved,
      emptyReplyAcknowledgementObserved: emptyReplyAcknowledgementObserved,
      replyPeerGenerationValidated: replyPeerGenerationValidated,
      connectionCancelRequested: true
    )
    let continuation = continuation
    self.continuation = nil
    continuation?.resume(returning: result)
  }
}
