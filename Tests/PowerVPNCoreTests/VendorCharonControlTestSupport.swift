import Foundation
@preconcurrency import XPC

@testable import PowerVPNCore

final class ControlTextMaterial: @unchecked Sendable, VendorCharonStartTextMaterial {
  private let lock = NSLock()
  private var storage: [UInt8]
  private var shouldFail = false

  init(_ text: String) {
    storage = Array(text.utf8)
  }

  var byteCount: Int { lock.withLock { storage.count } }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      if shouldFail { throw ControlTestError.materialUnavailable }
      return try storage.withUnsafeBytes(body)
    }
  }

  func failBorrows() {
    lock.withLock { shouldFail = true }
  }
}

enum ControlTestError: Error {
  case missingSnapshot
  case materialUnavailable
}

struct ControlSnapshotFixture {
  let lineage = VendorCharonStartLineage()
  let session = ControlTextMaterial("synthetic-session")
  let gateway = ControlTextMaterial("synthetic-gateway")

  func snapshot(
    tunnelNames: [String] = ["synthetic-tunnel"],
    selectedEncodedTunnelIndex: Int? = nil
  ) throws -> VendorCharonStartSnapshot {
    let candidate = VendorCharonStartCandidate(
      lineage: lineage,
      common: VendorCharonStartCommonCandidate(
        sessionID: text(session),
        gateway: text(gateway),
        ikePort: integer(500),
        majorVersion: integer(2),
        ike: text("aes128-sha1-modp1024"),
        esp: text("aes128-sha1"),
        psk: text("synthetic-psk"),
        ikeLifetime: integer(3_600),
        ipsecLifetime: integer(1_800)
      ),
      tunnels: tunnelNames.map { tunnelName in
        VendorCharonStartTunnelCandidate(
          authority: integer(1),
          status: integer(2),
          tunnelName: text(tunnelName),
          family: integer(4),
          resourceFlag: integer(0),
          name: text(""),
          routes: [],
          mapID: text("synthetic-map")
        )
      }
    )
    guard let snapshot = VendorCharonStartValidator.validate(candidate).snapshot else {
      throw ControlTestError.missingSnapshot
    }
    if let selectedEncodedTunnelIndex {
      guard
        let selected = snapshot.selectingTunnel(
          atEncodedIndex: selectedEncodedTunnelIndex
        )
      else {
        throw ControlTestError.missingSnapshot
      }
      return selected
    }
    return snapshot
  }

  private func text(_ value: String) -> VendorCharonStartTextValue {
    text(ControlTextMaterial(value))
  }

  private func text(_ value: ControlTextMaterial) -> VendorCharonStartTextValue {
    VendorCharonStartTextValue(
      value: value,
      source: .authenticatedPortalResource,
      lineage: lineage
    )
  }

  private func integer(_ value: Int32) -> VendorCharonStartIntegerValue {
    VendorCharonStartIntegerValue(
      value: value,
      source: .authenticatedPortalMetadata,
      lineage: lineage
    )
  }
}

struct ControlEnvelopeObservation: Equatable, Sendable {
  let operation: String?
  let exactStartShape: Bool
  let exactStopShape: Bool
  let exactNCRouteToggleShape: Bool
  let ncRouteEnabled: Bool?
  let tunnelName: String?
  let gateway: String?
}

final class ScriptedCharonControlDriver: @unchecked Sendable,
  VendorCharonControlConnectionDriving
{
  private let lock = NSLock()
  private var connectionHandler: (@Sendable (VendorCharonControlConnectionEvent) -> Void)?
  private var replyHandlers: [@Sendable (VendorCharonControlReplyEvent) -> Void] = []
  private var envelopes: [ControlEnvelopeObservation] = []
  private var startTunnelCounts: [Int] = []
  private var cancels = 0
  private var sessionValid = true

  func install(
    connectionHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) -> Self {
    lock.withLock { self.connectionHandler = connectionHandler }
    return self
  }

  func submit(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) -> VendorXPCSessionSubmission {
    guard lock.withLock({ sessionValid }) else {
      return .rejected(.connectionInvalid)
    }
    let operation = xpc_dictionary_get_string(request, "rpc").map(String.init(cString:))
    let common = try? dictionary(request, "common")
    let gateway = common.flatMap { try? string($0, "gateway") }
    let startTunnelCount = (try? array(request, "tunnels")).map(xpc_array_get_count)
    let startShape: Bool
    if operation == "start_connection" {
      startShape =
        hasExactKeys(request, ["type", "rpc", "common", "tunnels"])
        && (try? string(request, "type")) == "rpc"
        && common != nil
        && (try? array(request, "tunnels")) != nil
    } else {
      startShape = false
    }
    let stopShape =
      operation == "stop_connection"
      && hasExactKeys(request, ["type", "rpc", "common"])
      && (try? string(request, "type")) == "rpc"
      && common.map { hasExactKeys($0, ["gateway"]) } == true
      && gateway != nil
    let ncRouteToggleShape =
      operation == "updown_nc"
      && hasExactKeys(request, ["type", "rpc", "updown", "tunnel-name"])
      && (try? string(request, "type")) == "rpc"
      && xpc_dictionary_get_value(request, "updown")
        .map { xpc_get_type($0) == XPC_TYPE_BOOL } == true
      && xpc_dictionary_get_value(request, "tunnel-name")
        .map { xpc_get_type($0) == XPC_TYPE_STRING } == true
    let ncRouteEnabled =
      ncRouteToggleShape ? xpc_dictionary_get_bool(request, "updown") : nil
    let tunnelName =
      ncRouteToggleShape ? try? string(request, "tunnel-name") : nil
    lock.withLock {
      if operation == "start_connection", let startTunnelCount {
        startTunnelCounts.append(startTunnelCount)
      }
      envelopes.append(
        ControlEnvelopeObservation(
          operation: operation,
          exactStartShape: startShape,
          exactStopShape: stopShape,
          exactNCRouteToggleShape: ncRouteToggleShape,
          ncRouteEnabled: ncRouteEnabled,
          tunnelName: tunnelName,
          gateway: gateway
        ))
      replyHandlers.append(replyHandler)
    }
    return .submitted
  }

  func cancel() {
    lock.withLock { cancels += 1 }
  }

  var submitCount: Int { lock.withLock { replyHandlers.count } }
  var cancelCount: Int { lock.withLock { cancels } }
  var observations: [ControlEnvelopeObservation] { lock.withLock { envelopes } }
  var observedStartTunnelCounts: [Int] { lock.withLock { startTunnelCounts } }

  func emitReply(_ event: VendorCharonControlReplyEvent, at index: Int) {
    let handler = lock.withLock {
      return replyHandlers.indices.contains(index) ? replyHandlers[index] : nil
    }
    handler?(event)
  }
  func emitReplyDictionary(_ object: xpc_object_t, at index: Int) {
    guard let signature = VendorCharonControlWireCodec.dictionarySignature(object) else {
      preconditionFailure("expected XPC dictionary")
    }
    let event = VendorCharonControlWireCodec.replyEvent(object)
    emitReply(.decodedDictionary(signature: signature, event: event), at: index)
  }

  func invalidateSession() {
    let handler = lock.withLock {
      sessionValid = false
      return connectionHandler
    }
    handler?(.connectionInvalid)
  }

  func rejectFutureSubmissions() {
    lock.withLock { sessionValid = false }
  }

  func emitConnection(_ event: VendorCharonControlConnectionEvent) {
    let handler = lock.withLock { connectionHandler }
    handler?(event)
  }
  func emitConnectionDictionary(_ object: xpc_object_t) {
    guard let signature = VendorCharonControlWireCodec.dictionarySignature(object) else {
      preconditionFailure("expected XPC dictionary")
    }
    let event = VendorCharonControlWireCodec.connectionEvent(object)
    emitConnection(.decodedDictionary(signature: signature, event: event))
  }

}

final class CharonControlDriverFactory: @unchecked Sendable {
  let driver: ScriptedCharonControlDriver
  private let lock = NSLock()
  private var calls = 0

  init(driver: ScriptedCharonControlDriver = ScriptedCharonControlDriver()) {
    self.driver = driver
  }

  func make(
    queue _: DispatchQueue,
    handler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) -> any VendorCharonControlConnectionDriving {
    lock.withLock { calls += 1 }
    return driver.install(connectionHandler: handler)
  }

  var callCount: Int { lock.withLock { calls } }
}
final class ManualConnectionDrainScheduler: @unchecked Sendable {
  private let lock = NSLock()
  private var scheduledQueue: DispatchQueue?
  private var expiration: (@Sendable () -> Void)?
  private var cancellations = 0

  func schedule(
    queue: DispatchQueue,
    expiration: @escaping @Sendable () -> Void
  ) -> @Sendable () -> Void {
    lock.withLock {
      precondition(self.expiration == nil)
      scheduledQueue = queue
      self.expiration = expiration
    }
    return { [self] in
      lock.withLock {
        scheduledQueue = nil
        self.expiration = nil
        cancellations += 1
      }
    }
  }

  func expire() {
    let scheduled = lock.withLock { (scheduledQueue, expiration) }
    guard let queue = scheduled.0, let expiration = scheduled.1 else { return }
    queue.async(execute: expiration)
  }

  var isArmed: Bool { lock.withLock { expiration != nil } }
  var cancellationCount: Int { lock.withLock { cancellations } }
}

final class DrainCompletionProbe: @unchecked Sendable {
  private let lock = NSLock()
  private var completed = false

  func mark() {
    lock.withLock { completed = true }
  }

  var isComplete: Bool { lock.withLock { completed } }
}

func controlTransport(
  _ factory: CharonControlDriverFactory
) -> RawVendorCharonControlTransport {
  RawVendorCharonControlTransport(driverFactory: factory.make)
}

func waitForControl(
  _ condition: @escaping @Sendable () -> Bool,
  attempts: Int = 2_000
) async -> Bool {
  for _ in 0..<attempts {
    if condition() { return true }
    await Task.yield()
  }
  return condition()
}

func retainedStrings(in value: Any) -> [String] {
  if let string = value as? String { return [string] }
  return Mirror(reflecting: value).children.flatMap { retainedStrings(in: $0.value) }
}
