import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VICIRuntimeProbeTests {
  @Test func runsSyntheticLoadListUnloadWithoutCredentialOrInitiate() throws {
    let loadedEvent = VICIMessage(elements: [
      .section(name: VICIRuntimeProbe.syntheticConnectionName, elements: [])
    ])
    let transport = RuntimeScriptedTransport(responses: [
      response([.keyValue("daemon", "charon"), .keyValue("version", "6.0.7")]),
      operation(.eventConfirm),
      response([]),
      operation(.eventConfirm),
      successResponse(),
      operation(.eventConfirm),
      eventResponse("list-conn", loadedEvent),
      response([]),
      operation(.eventConfirm),
      successResponse(),
      operation(.eventConfirm),
      response([]),
      operation(.eventConfirm),
    ])
    let report = try VICIRuntimeProbe.smoke(session: VICISession(transport: transport))

    #expect(report.success)
    #expect(report.version.responseKeyNames == ["daemon", "version"])
    #expect(report.listAfterLoad.syntheticConnectionMatches == 1)
    #expect(report.listAfterUnload.syntheticConnectionMatches == 0)
    #expect(!report.clientActions.credentialRead)
    #expect(!report.clientActions.initiateCalled)
    #expect(!report.clientActions.installCalled)
    #expect(!report.secretValuesRetained)
    #expect(
      sentCommandNames(transport.sentPayloads) == [
        "version", "list-conns", "load-conn", "list-conns", "unload-conn", "list-conns",
      ])
  }

  @Test func unloadsBestEffortWhenLoadedConnectionIsNotObservedExactlyOnce() throws {
    let transport = RuntimeScriptedTransport(responses: [
      response([.keyValue("daemon", "charon")]),
      operation(.eventConfirm),
      response([]),
      operation(.eventConfirm),
      successResponse(),
      operation(.eventConfirm),
      response([]),
      operation(.eventConfirm),
      successResponse(),
    ])
    do {
      _ = try VICIRuntimeProbe.smoke(session: VICISession(transport: transport))
      Issue.record("expected observation failure")
    } catch let error as VICIRuntimeProbeError {
      #expect(error == .syntheticConnectionNotObserved(matches: 0, events: 0))
    }
    #expect(sentCommandNames(transport.sentPayloads).last == "unload-conn")
  }
}

private final class RuntimeScriptedTransport: VICIFrameTransport {
  private var responses: [VICIReceivedFrame]
  private(set) var sentPayloads: [Data] = []

  init(responses: [VICIReceivedFrame]) {
    self.responses = responses
  }

  func send(payload: Data) throws -> Int {
    sentPayloads.append(payload)
    return payload.count + 4
  }

  func receive() throws -> VICIReceivedFrame {
    guard !responses.isEmpty else { throw VICITransportError.timeout(.readHeader) }
    return responses.removeFirst()
  }

  func close() {}
}

private func response(_ elements: [VICIElement]) -> VICIReceivedFrame {
  let payload =
    Data([VICIPacketOperation.commandResponse.rawValue])
    + (try! VICIMessageCodec.encode(VICIMessage(elements: elements)))
  return VICIReceivedFrame(payload: payload, wireByteCount: payload.count + 4)
}

private func successResponse() -> VICIReceivedFrame {
  response([.keyValue("success", "yes")])
}

private func operation(_ operation: VICIPacketOperation) -> VICIReceivedFrame {
  let payload = Data([operation.rawValue])
  return VICIReceivedFrame(payload: payload, wireByteCount: payload.count + 4)
}

private func eventResponse(_ name: String, _ message: VICIMessage) -> VICIReceivedFrame {
  let payload =
    Data([VICIPacketOperation.event.rawValue, UInt8(name.utf8.count)])
    + Data(name.utf8) + (try! VICIMessageCodec.encode(message))
  return VICIReceivedFrame(payload: payload, wireByteCount: payload.count + 4)
}

private func sentCommandNames(_ payloads: [Data]) -> [String] {
  payloads.compactMap { payload in
    guard payload.first == VICIPacketOperation.commandRequest.rawValue,
      let request = try? VICINamedRequest.decode(payload: payload)
    else { return nil }
    return request.command
  }
}
