import Dispatch
@preconcurrency import XPC

protocol VendorCharonEmergencyConnectionDriving: AnyObject, Sendable {
  func beginProbe(_ request: xpc_object_t)

  func submitStop(
    _ request: xpc_object_t,
    expectedPeerPID: Int32,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> Bool

  func cancel()
}

/// One fixed-service XPC connection used first for exact peer authentication
/// and then, only on that authenticated connection, for exact emergency stop.
final class SystemVendorCharonEmergencyConnectionDriver: @unchecked Sendable,
  VendorCharonEmergencyConnectionDriving
{
  private enum Phase { case probing, stopping, closed }

  static let serviceName = "com.leadsec.charon-xpc"

  private let connection: xpc_connection_t
  private let queue: DispatchQueue
  private let probeEventHandler: @Sendable (VendorXPCConnectionEvent) -> Void
  private let probeReplyHandler: @Sendable (VendorXPCReplyCallbackEvent) -> Void
  private let stopEventHandler: @Sendable (VendorCharonControlConnectionEvent) -> Void
  private var phase = Phase.probing

  init(
    queue: DispatchQueue,
    probeEventHandler: @escaping @Sendable (VendorXPCConnectionEvent) -> Void,
    probeReplyHandler: @escaping @Sendable (VendorXPCReplyCallbackEvent) -> Void,
    stopEventHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) {
    self.queue = queue
    self.probeEventHandler = probeEventHandler
    self.probeReplyHandler = probeReplyHandler
    self.stopEventHandler = stopEventHandler
    connection = Self.serviceName.withCString { service in
      xpc_connection_create_mach_service(
        service,
        queue,
        UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED)
      )
    }
  }

  func beginProbe(_ request: xpc_object_t) {
    guard phase == .probing else { return }
    xpc_connection_set_event_handler(connection) { [self] object in
      switch phase {
      case .probing:
        probeEventHandler(
          VendorXPCWireCodec.connectionEvent(
            object,
            peerPID: xpc_connection_get_pid(connection)
          ))
      case .stopping:
        stopEventHandler(VendorCharonControlWireCodec.connectionEvent(object))
      case .closed:
        break
      }
    }
    xpc_connection_activate(connection)
    xpc_connection_send_message_with_reply(
      connection,
      request,
      queue
    ) { [probeReplyHandler] object in
      probeReplyHandler(VendorXPCWireCodec.replyCallback(object))
    }
  }

  func submitStop(
    _ request: xpc_object_t,
    expectedPeerPID: Int32,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> Bool {
    guard phase == .probing else {
      return false
    }
    let currentPeerPID = xpc_connection_get_pid(connection)
    guard currentPeerPID > 0, currentPeerPID == expectedPeerPID else {
      return false
    }
    phase = .stopping
    xpc_connection_send_message_with_reply(
      connection,
      request,
      queue
    ) { [connection] object in
      replyHandler(
        VendorCharonControlWireCodec.replyEvent(
          object,
          peerPID: xpc_connection_get_pid(connection)
        ))
    }
    return true
  }

  func cancel() {
    guard phase != .closed else { return }
    phase = .closed
    xpc_connection_set_event_handler(connection) { _ in }
    xpc_connection_cancel(connection)
  }
}
