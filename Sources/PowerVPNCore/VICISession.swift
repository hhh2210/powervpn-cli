import CryptoKit
import Foundation

public struct VICIExchangeTrace: Codable, Equatable, Sendable {
  public let command: String
  public let requestPayloadBytes: Int
  public let requestWireBytes: Int
  public let requestPayloadSHA256: String
  public let responsePayloadBytes: Int
  public let responseWireBytes: Int
  public let responsePayloadSHA256: String
  public let responseOperation: VICIPacketOperation
  public let latencyMilliseconds: Int
}

public struct VICICommandResult: Equatable, Sendable {
  public let message: VICIMessage
  public let trace: VICIExchangeTrace
}

public struct VICIStreamResult: Equatable, Sendable {
  public let events: [VICIMessage]
  public let traces: [VICIExchangeTrace]
}

public enum VICISessionError: Error, Equatable, CustomStringConvertible, Sendable {
  case commandUnknown(String)
  case commandFailed(String)
  case unexpectedPacket(expected: String, actual: VICIPacketOperation)
  case unexpectedEvent(expected: String, actual: String)
  case eventUnknown(String)

  public var description: String {
    switch self {
    case .commandUnknown(let command):
      return "VICI daemon does not recognize command \(command)"
    case .commandFailed(let command):
      return "VICI daemon rejected command \(command)"
    case .unexpectedPacket(let expected, let actual):
      return "VICI expected \(expected), received operation \(actual.rawValue)"
    case .unexpectedEvent(let expected, let actual):
      return "VICI expected event \(expected), received \(actual)"
    case .eventUnknown(let event):
      return "VICI daemon does not recognize event \(event)"
    }
  }
}

public final class VICISession {
  private let transport: any VICIFrameTransport

  public convenience init(socketPath: String, timeoutMilliseconds: Int = 2_000) throws {
    try self.init(
      transport: VICIUnixTransport(
        socketPath: socketPath,
        timeoutMilliseconds: timeoutMilliseconds
      )
    )
  }

  init(transport: any VICIFrameTransport) {
    self.transport = transport
  }

  deinit {
    transport.close()
  }

  public func version() throws -> VICICommandResult {
    try request(command: "version")
  }

  public func request(
    command: String,
    message: VICIMessage = VICIMessage(elements: [])
  ) throws -> VICICommandResult {
    let request = VICINamedRequest(command: command, message: message)
    let payload = try request.encodedPayload()
    let started = ContinuousClock.now
    let writeBytes = try transport.send(payload: payload)
    let frame = try transport.receive()
    let packet = try VICIPacketCodec.decodeResponse(frame.payload)
    let trace = VICIExchangeTrace(
      command: command,
      requestPayloadBytes: payload.count,
      requestWireBytes: writeBytes,
      requestPayloadSHA256: sha256(payload),
      responsePayloadBytes: frame.payload.count,
      responseWireBytes: frame.wireByteCount,
      responsePayloadSHA256: sha256(frame.payload),
      responseOperation: packet.operation,
      latencyMilliseconds: elapsedMilliseconds(since: started)
    )
    switch packet {
    case .commandResponse(let response):
      try validateCommandResponse(response, command: command)
      return VICICommandResult(message: response, trace: trace)
    case .commandUnknown:
      throw VICISessionError.commandUnknown(command)
    default:
      throw VICISessionError.unexpectedPacket(
        expected: "command response", actual: packet.operation
      )
    }
  }

  public func streamedRequest(
    command: String,
    event: String,
    message: VICIMessage = VICIMessage(elements: [])
  ) throws -> VICIStreamResult {
    var traces: [VICIExchangeTrace] = []
    traces.append(try setEventRegistration(event, register: true))
    var registered = true
    do {
      let request = VICINamedRequest(command: command, message: message)
      let payload = try request.encodedPayload()
      let started = ContinuousClock.now
      let writeBytes = try transport.send(payload: payload)
      var events: [VICIMessage] = []
      while true {
        let frame = try transport.receive()
        let packet = try VICIPacketCodec.decodeResponse(frame.payload)
        traces.append(
          VICIExchangeTrace(
            command: command,
            requestPayloadBytes: payload.count,
            requestWireBytes: writeBytes,
            requestPayloadSHA256: sha256(payload),
            responsePayloadBytes: frame.payload.count,
            responseWireBytes: frame.wireByteCount,
            responsePayloadSHA256: sha256(frame.payload),
            responseOperation: packet.operation,
            latencyMilliseconds: elapsedMilliseconds(since: started)
          )
        )
        switch packet {
        case .event(let actual, let message):
          guard actual == event else {
            throw VICISessionError.unexpectedEvent(expected: event, actual: actual)
          }
          events.append(message)
        case .commandResponse(let response):
          traces.append(try setEventRegistration(event, register: false))
          registered = false
          try validateCommandResponse(response, command: command)
          return VICIStreamResult(events: events, traces: traces)
        case .commandUnknown:
          throw VICISessionError.commandUnknown(command)
        default:
          throw VICISessionError.unexpectedPacket(
            expected: "stream event or command response", actual: packet.operation
          )
        }
      }
    } catch {
      if registered {
        _ = try? setEventRegistration(event, register: false)
      }
      throw error
    }
  }

  public func close() {
    transport.close()
  }

  private func setEventRegistration(_ event: String, register: Bool) throws -> VICIExchangeTrace {
    let payload = try VICIPacketCodec.encodeEventRegistration(event, register: register)
    let started = ContinuousClock.now
    let writeBytes = try transport.send(payload: payload)
    let command = register ? "register:\(event)" : "unregister:\(event)"
    for _ in 0..<32 {
      let frame = try transport.receive()
      let packet = try VICIPacketCodec.decodeResponse(frame.payload)
      let trace = VICIExchangeTrace(
        command: command,
        requestPayloadBytes: payload.count,
        requestWireBytes: writeBytes,
        requestPayloadSHA256: sha256(payload),
        responsePayloadBytes: frame.payload.count,
        responseWireBytes: frame.wireByteCount,
        responsePayloadSHA256: sha256(frame.payload),
        responseOperation: packet.operation,
        latencyMilliseconds: elapsedMilliseconds(since: started)
      )
      switch packet {
      case .eventConfirm:
        return trace
      case .event(let actual, _):
        guard actual == event else {
          throw VICISessionError.unexpectedEvent(expected: event, actual: actual)
        }
      case .eventUnknown:
        throw VICISessionError.eventUnknown(event)
      default:
        throw VICISessionError.unexpectedPacket(
          expected: "event confirmation", actual: packet.operation
        )
      }
    }
    throw VICISessionError.unexpectedPacket(
      expected: "bounded event confirmation", actual: .event
    )
  }

  private func validateCommandResponse(_ response: VICIMessage, command: String) throws {
    if let success = response.value(forKey: "success"), success != Data("yes".utf8) {
      throw VICISessionError.commandFailed(command)
    }
  }
}

extension VICIMessage {
  var topLevelNames: [String] {
    elements.map(\.name)
  }

  func value(forKey key: String) -> Data? {
    for element in elements {
      if case .keyValue(let name, let value) = element, name == key {
        return value
      }
    }
    return nil
  }

  func containsTopLevelSection(named name: String) -> Bool {
    elements.contains { element in
      if case .section(let sectionName, _) = element {
        return sectionName == name
      }
      return false
    }
  }
}

private func sha256(_ data: Data) -> String {
  SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func elapsedMilliseconds(since start: ContinuousClock.Instant) -> Int {
  let duration = start.duration(to: .now)
  let components = duration.components
  let seconds = components.seconds * 1_000
  let attoseconds = components.attoseconds / 1_000_000_000_000_000
  return Int(seconds + attoseconds)
}
