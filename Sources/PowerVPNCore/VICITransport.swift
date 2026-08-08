import Foundation

public enum VICITransportPhase: String, Codable, Equatable, Sendable {
  case connect
  case writeFrame
  case readHeader
  case readPayload
}

public enum VICITransportError: Error, Equatable, CustomStringConvertible, Sendable {
  case invalidTimeout
  case invalidSocketPath
  case socketCreationFailed(Int32)
  case socketConfigurationFailed(Int32)
  case connectFailed(Int32)
  case timeout(VICITransportPhase)
  case writeFailed(Int32)
  case readFailed(VICITransportPhase, Int32)
  case unexpectedEOF(VICITransportPhase, expected: Int, received: Int)
  case frameTooLarge(Int)
  case emptyFrame

  public var description: String {
    switch self {
    case .invalidTimeout:
      return "VICI timeout must be between 1 and 60000 milliseconds"
    case .invalidSocketPath:
      return "VICI Unix socket path is empty or exceeds sockaddr_un capacity"
    case .socketCreationFailed(let code):
      return "VICI socket creation failed with errno \(code)"
    case .socketConfigurationFailed(let code):
      return "VICI socket configuration failed with errno \(code)"
    case .connectFailed(let code):
      return "VICI socket connect failed with errno \(code)"
    case .timeout(let phase):
      return "VICI transport timed out during \(phase.rawValue)"
    case .writeFailed(let code):
      return "VICI frame write failed with errno \(code)"
    case .readFailed(let phase, let code):
      return "VICI frame read failed during \(phase.rawValue) with errno \(code)"
    case .unexpectedEOF(let phase, let expected, let received):
      return "VICI peer closed during \(phase.rawValue) after \(received) of \(expected) bytes"
    case .frameTooLarge(let size):
      return "VICI frame length \(size) exceeds the 512 KiB limit"
    case .emptyFrame:
      return "VICI daemon returned an empty frame"
    }
  }
}

public struct VICIReceivedFrame: Equatable, Sendable {
  public let payload: Data
  public let wireByteCount: Int

  public init(payload: Data, wireByteCount: Int) {
    self.payload = payload
    self.wireByteCount = wireByteCount
  }
}

protocol VICIFrameTransport: AnyObject {
  func send(payload: Data) throws -> Int
  func receive() throws -> VICIReceivedFrame
  func close()
}
