import Darwin
import Foundation
import Security

enum M2TTYApprovalOutcome: String, Equatable, Sendable {
  case accepted
  case denied
  case unavailable
}

enum M2TTYLineRead: Equatable, Sendable {
  case line(String)
  case unavailable
}

struct M2TTYApproval: Sendable {
  typealias Exchange = @Sendable (String) -> M2TTYLineRead

  private let exchange: Exchange

  init(exchange: @escaping Exchange = currentTerminalExchange) {
    self.exchange = exchange
  }

  func request(
    code: String,
    resourceDisplayName: String,
    sshTarget: String
  ) -> M2TTYApprovalOutcome {
    guard Self.validCode(code) else { return .unavailable }
    let prompt =
      "PowerVPN M2 one-time approval\n"
      + "Resource: \(resourceDisplayName)\n"
      + "SSH target: \(sshTarget)\n"
      + "This will perform one Portal login, start_connection, fresh SSH proof, stop, and cleanup.\n"
      + "Type \(code) exactly and press Return to continue: "
    switch exchange(prompt) {
    case .line(let response): return response == code ? .accepted : .denied
    case .unavailable: return .unavailable
    }
  }

  static func secureCode() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 4)
    let status = bytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else { throw M2TTYApprovalError.randomFailed }
    let digits = Array("0123456789ABCDEF".utf8)
    var encoded = [UInt8]()
    encoded.reserveCapacity(8)
    for byte in bytes {
      encoded.append(digits[Int(byte >> 4)])
      encoded.append(digits[Int(byte & 0x0F)])
    }
    return String(decoding: encoded, as: UTF8.self)
  }

  static func validCode(_ code: String) -> Bool {
    code.utf8.count == 8
      && code.utf8.allSatisfy {
        (0x30...0x39).contains($0) || (0x41...0x46).contains($0)
      }
  }

  private static func currentTerminalExchange(_ prompt: String) -> M2TTYLineRead {
    let descriptor = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY)
    guard descriptor >= 0 else { return .unavailable }
    defer { close(descriptor) }
    guard isatty(descriptor) == 1, writeAll(Data(prompt.utf8), to: descriptor) else {
      return .unavailable
    }
    var response = [UInt8]()
    response.reserveCapacity(8)
    while response.count <= 8 {
      var byte: UInt8 = 0
      let count = read(descriptor, &byte, 1)
      if count == 1 {
        if byte == 0x0A { return .line(String(decoding: response, as: UTF8.self)) }
        response.append(byte)
      } else if count == 0 {
        return .unavailable
      } else if errno != EINTR {
        return .unavailable
      }
    }
    return .line("")
  }

  private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
    data.withUnsafeBytes { buffer in
      guard let base = buffer.baseAddress else { return true }
      var written = 0
      while written < buffer.count {
        let count = write(descriptor, base.advanced(by: written), buffer.count - written)
        if count > 0 {
          written += count
        } else if count < 0, errno == EINTR {
          continue
        } else {
          return false
        }
      }
      return true
    }
  }
}

private enum M2TTYApprovalError: Error {
  case randomFailed
}
