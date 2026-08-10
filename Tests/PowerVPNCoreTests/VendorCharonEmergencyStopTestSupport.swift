import Dispatch
import Foundation
@preconcurrency import XPC

@testable import PowerVPNCore

enum EmergencyEnvelopeObservation: Equatable, Sendable {
  case getVersion
  case stopConnection
  case unexpected
}

final class ScriptedEmergencyConnectionDriver: @unchecked Sendable,
  VendorCharonEmergencyConnectionDriving
{
  private let lock = NSLock()
  private let probeEventHandler: @Sendable (VendorCharonEmergencyProbeEvent) -> Void
  private let probeReplyHandler: @Sendable (VendorXPCReplyCallbackEvent) -> Void
  private let stopEventHandler: @Sendable (VendorCharonControlConnectionEvent) -> Void
  private var stopReplyHandler: (@Sendable (VendorCharonControlReplyEvent) -> Void)?
  private var envelopes: [EmergencyEnvelopeObservation] = []
  private var probes = 0
  private var stops = 0
  private var cancels = 0
  private var sessionValid = true

  init(
    probeEventHandler: @escaping @Sendable (VendorCharonEmergencyProbeEvent) -> Void,
    probeReplyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void,
    stopEventHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) {
    self.probeEventHandler = probeEventHandler
    self.probeReplyHandler = probeReplyHandler
    self.stopEventHandler = stopEventHandler
  }

  func beginProbe(_ request: xpc_object_t) -> VendorXPCSessionSubmission {
    lock.withLock {
      guard sessionValid else { return .rejected(.connectionInvalid) }
      probes += 1
      envelopes.append(Self.observation(request))
      return .submitted
    }
  }

  func submitStop(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> VendorXPCSessionSubmission {
    lock.withLock {
      guard sessionValid else { return .rejected(.connectionInvalid) }
      stops += 1
      envelopes.append(Self.observation(request))
      stopReplyHandler = replyHandler
      return .submitted
    }
  }

  func cancel() {
    lock.withLock { cancels += 1 }
  }

  var observations: [EmergencyEnvelopeObservation] { lock.withLock { envelopes } }
  var probeCount: Int { lock.withLock { probes } }
  var stopCount: Int { lock.withLock { stops } }
  var cancelCount: Int { lock.withLock { cancels } }

  func emitProbeBusiness() {
    emitProbe(
      .business(
        VendorXPCBusinessReply(
          versionByteLength: 5,
          versionMatchesLockedBuild: true,
          getVersionSuccess: true
        )
      ))
  }

  func invalidateSession() {
    lock.withLock { sessionValid = false }
  }

  func emitProbe(_ event: VendorCharonEmergencyProbeEvent) {
    probeEventHandler(event)
  }

  func emitProbeReply(_ event: VendorXPCReplyCallbackEvent) {
    probeReplyHandler(event)
  }

  func emitStopEvent(_ event: VendorCharonControlConnectionEvent) {
    stopEventHandler(event)
  }

  func emitStopReply(_ event: VendorCharonControlReplyEvent) {
    lock.withLock { stopReplyHandler }?(event)
  }

  private static func observation(_ request: xpc_object_t) -> EmergencyEnvelopeObservation {
    guard xpc_dictionary_get_count(request) == 2,
      let type = xpc_dictionary_get_string(request, "type"),
      let rpc = xpc_dictionary_get_string(request, "rpc"),
      String(cString: type) == "rpc"
    else { return .unexpected }
    switch String(cString: rpc) {
    case "get_version": return .getVersion
    case "stop_connection": return .stopConnection
    default: return .unexpected
    }
  }
}

final class EmergencyConnectionDriverFactory: @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0
  private var storedDriver: ScriptedEmergencyConnectionDriver?

  func make(
    queue _: DispatchQueue,
    probeEventHandler: @escaping @Sendable (VendorCharonEmergencyProbeEvent) -> Void,
    probeReplyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void,
    stopEventHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) -> any VendorCharonEmergencyConnectionDriving {
    let driver = ScriptedEmergencyConnectionDriver(
      probeEventHandler: probeEventHandler,
      probeReplyHandler: probeReplyHandler,
      stopEventHandler: stopEventHandler
    )
    lock.withLock {
      calls += 1
      storedDriver = driver
    }
    return driver
  }

  var callCount: Int { lock.withLock { calls } }

  var driver: ScriptedEmergencyConnectionDriver {
    lock.withLock { storedDriver }
      ?? ScriptedEmergencyConnectionDriver(
        probeEventHandler: { _ in },
        probeReplyHandler: { _ in },
        stopEventHandler: { _ in }
      )
  }
}

func emergencyTransport(
  _ factory: EmergencyConnectionDriverFactory
) -> RawVendorCharonControlTransport {
  let normal = CharonControlDriverFactory()
  return RawVendorCharonControlTransport(
    driverFactory: normal.make,
    emergencyDriverFactory: factory.make
  )
}

func emergencyStopTask(
  _ factory: EmergencyConnectionDriverFactory,
  gate: @escaping @Sendable () async -> Bool = { true },
  peerGenerationValidator: @escaping @Sendable () async -> Bool = { true }
) -> Task<VendorCharonControlReceipt, Never> {
  Task {
    await emergencyTransport(factory).emergencyStop(
      timeoutMilliseconds: 500,
      expectedRunningPredicate: gate,
      peerGenerationValidator: peerGenerationValidator
    )
  }
}

final class EmergencyStopGate: @unchecked Sendable {
  private let lock = NSLock()
  private let factory: EmergencyConnectionDriverFactory
  private let result: Bool
  private var calls = 0
  private var observedFactoryCalls: [Int] = []

  init(factory: EmergencyConnectionDriverFactory, result: Bool) {
    self.factory = factory
    self.result = result
  }

  func evaluate() -> Bool {
    lock.withLock {
      calls += 1
      observedFactoryCalls.append(factory.callCount)
      return result
    }
  }

  var callCount: Int { lock.withLock { calls } }
  var factoryCallsObserved: [Int] { lock.withLock { observedFactoryCalls } }
}
