import Dispatch
@preconcurrency import XPC

enum VendorCharonEmergencyProbeEvent: Equatable, Sendable {
  case business(VendorXPCBusinessReply)
  case emptyDispatcherTail
  case malformedBusinessEvent
  case connectionInterrupted
  case connectionInvalid
  case peerCodeSigningRequirement
  case unexpectedXPCError
  case unexpectedConnectionEvent
}

protocol VendorCharonEmergencyConnectionDriving: AnyObject, Sendable {
  func beginProbe(_ request: xpc_object_t) -> VendorXPCSessionSubmission

  func submitStop(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> VendorXPCSessionSubmission

  func cancel()
}

/// One fixed-service, non-reconnecting XPC session used for probe then stop.
final class SystemVendorCharonEmergencyConnectionDriver: @unchecked Sendable,
  VendorCharonEmergencyConnectionDriving
{
  private enum Phase { case probing, stopping, closed }

  static let serviceName = "com.leadsec.charon-xpc"

  private let probeEventHandler: @Sendable (VendorCharonEmergencyProbeEvent) -> Void
  private let probeReplyHandler: @Sendable (VendorXPCReplyCallbackEvent) -> Void
  private let stopEventHandler: @Sendable (VendorCharonControlConnectionEvent) -> Void
  private var session: VendorXPCSession!
  private var phase = Phase.probing

  init(
    queue: DispatchQueue,
    probeEventHandler: @escaping @Sendable (VendorCharonEmergencyProbeEvent) -> Void,
    probeReplyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void,
    stopEventHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) {
    self.probeEventHandler = probeEventHandler
    self.probeReplyHandler = probeReplyHandler
    self.stopEventHandler = stopEventHandler
    session = VendorXPCSession(
      queue: queue,
      incomingDecoder: { [weak self] object in self?.handleIncoming(object) },
      cancellationHandler: { [weak self] outcome in self?.handleCancellation(outcome) }
    )
  }

  func beginProbe(_ request: xpc_object_t) -> VendorXPCSessionSubmission {
    guard phase == .probing else { return .rejected(.connectionInvalid) }
    return session.send(
      request,
      replyDecoder: { [probeReplyHandler] object in
        probeReplyHandler(VendorXPCWireCodec.replyCallback(object))
      },
      failureHandler: { [probeReplyHandler] outcome in
        probeReplyHandler(Self.probeReplyEvent(outcome))
      }
    )
  }

  func submitStop(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> VendorXPCSessionSubmission {
    guard phase == .probing else { return .rejected(.connectionInvalid) }
    let submission = session.send(
      request,
      replyDecoder: { object in
        replyHandler(VendorCharonControlWireCodec.replyEvent(object))
      },
      failureHandler: { outcome in
        replyHandler(Self.stopReplyEvent(outcome))
      }
    )
    guard submission == .submitted else { return submission }
    phase = .stopping
    return .submitted
  }

  func cancel() {
    guard phase != .closed else { return }
    phase = .closed
    session.cancel()
  }

  private func handleIncoming(_ object: xpc_object_t) {
    switch phase {
    case .probing:
      probeEventHandler(VendorXPCWireCodec.sessionConnectionEvent(object))
    case .stopping:
      stopEventHandler(VendorCharonControlWireCodec.connectionEvent(object))
    case .closed:
      break
    }
  }

  private func handleCancellation(_ outcome: VendorCharonControlOutcome) {
    switch phase {
    case .probing:
      probeEventHandler(Self.probeEvent(outcome))
    case .stopping:
      stopEventHandler(Self.controlEvent(outcome))
    case .closed:
      break
    }
  }

  private static func probeEvent(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonEmergencyProbeEvent {
    switch outcome {
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .connectionInvalid: return .connectionInvalid
    default: return .unexpectedXPCError
    }
  }

  private static func controlEvent(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonControlConnectionEvent {
    switch outcome {
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .connectionInvalid: return .connectionInvalid
    default: return .unexpectedXPCError
    }
  }

  private static func probeReplyEvent(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorXPCReplyCallbackEvent {
    switch outcome {
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .connectionInvalid: return .connectionInvalid
    default: return .unexpectedXPCError
    }
  }

  private static func stopReplyEvent(
    _ outcome: VendorCharonControlOutcome
  ) -> VendorCharonControlReplyEvent {
    switch outcome {
    case .peerCodeSigningRequirement: return .peerCodeSigningRequirement
    case .connectionInvalid: return .connectionInvalid
    default: return .unexpectedXPCError
    }
  }
}
