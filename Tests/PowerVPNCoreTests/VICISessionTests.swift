import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VICISessionTests {
  @Test func streamsEventsBetweenBoundedRegisterAndUnregister() throws {
    let eventMessage = VICIMessage(elements: [
      .section(name: "cp7a.invalid", elements: [.keyValue("version", "IKEv1")])
    ])
    let transport = ScriptedVICITransport(responses: [
      packet(.eventConfirm),
      packet(.event(name: "list-conn", message: eventMessage)),
      packet(.commandResponse(VICIMessage(elements: []))),
      packet(.eventConfirm),
    ])
    let result = try VICISession(transport: transport).streamedRequest(
      command: "list-conns",
      event: "list-conn"
    )

    #expect(result.events == [eventMessage])
    #expect(transport.sentPayloads.count == 3)
    #expect(transport.sentPayloads[0].first == VICIPacketOperation.eventRegister.rawValue)
    #expect(transport.sentPayloads[1].first == VICIPacketOperation.commandRequest.rawValue)
    #expect(transport.sentPayloads[2].first == VICIPacketOperation.eventUnregister.rawValue)
    #expect(
      result.traces.map(\.responseOperation) == [
        .eventConfirm, .event, .commandResponse, .eventConfirm,
      ])
  }

  @Test func failsClosedOnUnknownCommand() throws {
    let transport = ScriptedVICITransport(responses: [packet(.commandUnknown)])
    do {
      _ = try VICISession(transport: transport).version()
      Issue.record("expected unknown command")
    } catch let error as VICISessionError {
      #expect(error == .commandUnknown("version"))
    }
  }

  @Test func failsClosedOnDaemonSuccessNoWithoutLeakingErrmsg() throws {
    let rejected = VICIMessage(elements: [
      .keyValue("success", "no"),
      .keyValue("errmsg", "synthetic private detail"),
    ])
    let transport = ScriptedVICITransport(responses: [packet(.commandResponse(rejected))])
    do {
      _ = try VICISession(transport: transport).request(command: "load-conn")
      Issue.record("expected command rejection")
    } catch let error as VICISessionError {
      #expect(error == .commandFailed("load-conn"))
      #expect(!error.description.contains("synthetic private detail"))
    }
  }

  @Test func drainsExpectedEventsUntilRegistrationConfirmation() throws {
    let transport = ScriptedVICITransport(responses: [
      packet(.event(name: "list-conn", message: VICIMessage(elements: []))),
      packet(.eventConfirm),
      packet(.commandResponse(VICIMessage(elements: []))),
      packet(.eventConfirm),
    ])
    let result = try VICISession(transport: transport).streamedRequest(
      command: "list-conns",
      event: "list-conn"
    )
    #expect(result.events.isEmpty)
  }

  @Test func streamedCommandRejectsTerminalSuccessNoAfterUnregistering() throws {
    let rejected = VICIMessage(elements: [
      .keyValue("success", "no"),
      .keyValue("errmsg", "synthetic private detail"),
    ])
    let transport = ScriptedVICITransport(responses: [
      packet(.eventConfirm),
      packet(.commandResponse(rejected)),
      packet(.eventConfirm),
    ])
    do {
      _ = try VICISession(transport: transport).streamedRequest(
        command: "list-conns",
        event: "list-conn"
      )
      Issue.record("expected streamed command rejection")
    } catch let error as VICISessionError {
      #expect(error == .commandFailed("list-conns"))
      #expect(!error.description.contains("synthetic private detail"))
    }
    #expect(transport.sentPayloads.count == 3)
    #expect(transport.sentPayloads.last?.first == VICIPacketOperation.eventUnregister.rawValue)
  }

  @Test func rejectsUnexpectedEventNameAndAttemptsCleanup() throws {
    let transport = ScriptedVICITransport(responses: [
      packet(.eventConfirm),
      packet(.event(name: "wrong-event", message: VICIMessage(elements: []))),
      packet(.eventConfirm),
    ])
    do {
      _ = try VICISession(transport: transport).streamedRequest(
        command: "list-conns",
        event: "list-conn"
      )
      Issue.record("expected unexpected event")
    } catch let error as VICISessionError {
      #expect(error == .unexpectedEvent(expected: "list-conn", actual: "wrong-event"))
    }
    #expect(transport.sentPayloads.last?.first == VICIPacketOperation.eventUnregister.rawValue)
  }
}

private final class ScriptedVICITransport: VICIFrameTransport {
  private var responses: [VICIReceivedFrame]
  private(set) var sentPayloads: [Data] = []
  private(set) var closed = false

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

  func close() {
    closed = true
  }
}

private func packet(_ packet: VICIPacket) -> VICIReceivedFrame {
  let payload: Data
  switch packet {
  case .commandResponse(let message):
    payload =
      Data([VICIPacketOperation.commandResponse.rawValue])
      + (try! VICIMessageCodec.encode(message))
  case .commandUnknown:
    payload = Data([VICIPacketOperation.commandUnknown.rawValue])
  case .eventConfirm:
    payload = Data([VICIPacketOperation.eventConfirm.rawValue])
  case .eventUnknown:
    payload = Data([VICIPacketOperation.eventUnknown.rawValue])
  case .event(let name, let message):
    payload =
      Data([VICIPacketOperation.event.rawValue, UInt8(name.utf8.count)])
      + Data(name.utf8) + (try! VICIMessageCodec.encode(message))
  }
  return VICIReceivedFrame(payload: payload, wireByteCount: payload.count + 4)
}
