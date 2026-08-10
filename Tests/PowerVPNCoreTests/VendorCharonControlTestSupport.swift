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

  func snapshot() throws -> VendorCharonStartSnapshot {
    let candidate = VendorCharonStartCandidate(
      lineage: lineage,
      common: VendorCharonStartCommonCandidate(
        sessionID: text(session),
        gateway: text("synthetic-gateway"),
        ikePort: integer(500),
        majorVersion: integer(2),
        ike: text("aes128-sha1-modp1024"),
        esp: text("aes128-sha1"),
        psk: text("synthetic-psk"),
        ikeLifetime: integer(3_600),
        ipsecLifetime: integer(1_800)
      ),
      tunnels: [
        VendorCharonStartTunnelCandidate(
          authority: integer(1),
          status: integer(2),
          tunnelName: text("synthetic-tunnel"),
          family: integer(4),
          resourceFlag: integer(0),
          name: text(""),
          routes: [],
          mapID: text("synthetic-map")
        )
      ]
    )
    guard let snapshot = VendorCharonStartValidator.validate(candidate).snapshot else {
      throw ControlTestError.missingSnapshot
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
}

final class ScriptedCharonControlDriver: @unchecked Sendable,
  VendorCharonControlConnectionDriving
{
  private let lock = NSLock()
  private var connectionHandler: (@Sendable (VendorCharonControlConnectionEvent) -> Void)?
  private var replyHandlers: [@Sendable (VendorCharonControlReplyEvent) -> Void] = []
  private var envelopes: [ControlEnvelopeObservation] = []
  private var cancels = 0

  func install(
    connectionHandler: @escaping @Sendable (VendorCharonControlConnectionEvent) -> Void
  ) -> Self {
    lock.withLock { self.connectionHandler = connectionHandler }
    return self
  }

  func submit(
    _ request: xpc_object_t,
    replyHandler: @escaping @Sendable (VendorCharonControlReplyEvent) -> Void
  ) {
    let operation = xpc_dictionary_get_string(request, "rpc").map(String.init(cString:))
    let startShape: Bool
    if operation == "start_connection" {
      startShape =
        hasExactKeys(request, ["type", "rpc", "common", "tunnels"])
        && (try? string(request, "type")) == "rpc"
        && (try? dictionary(request, "common")) != nil
        && (try? array(request, "tunnels")) != nil
    } else {
      startShape = false
    }
    let stopShape =
      operation == "stop_connection"
      && hasExactKeys(request, ["type", "rpc"])
      && (try? string(request, "type")) == "rpc"
    lock.withLock {
      envelopes.append(
        ControlEnvelopeObservation(
          operation: operation,
          exactStartShape: startShape,
          exactStopShape: stopShape
        ))
      replyHandlers.append(replyHandler)
    }
  }

  func cancel() {
    lock.withLock { cancels += 1 }
  }

  var submitCount: Int { lock.withLock { replyHandlers.count } }
  var cancelCount: Int { lock.withLock { cancels } }
  var observations: [ControlEnvelopeObservation] { lock.withLock { envelopes } }

  func emitReply(_ event: VendorCharonControlReplyEvent, at index: Int) {
    let handler = lock.withLock {
      replyHandlers.indices.contains(index) ? replyHandlers[index] : nil
    }
    handler?(event)
  }

  func emitConnection(_ event: VendorCharonControlConnectionEvent) {
    let handler = lock.withLock { connectionHandler }
    handler?(event)
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
