import Darwin
import Dispatch
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
  typealias AsyncExchange = @Sendable (String, UInt64) async -> M2TTYLineRead

  private let exchange: Exchange
  private let asyncExchange: AsyncExchange

  init() {
    exchange = Self.currentTerminalExchange
    asyncExchange = Self.currentCancellableTerminalExchange
  }

  init(exchange: @escaping Exchange) {
    self.exchange = exchange
    asyncExchange = { prompt, _ in exchange(prompt) }
  }

  init(
    exchange: @escaping Exchange,
    asyncExchange: @escaping AsyncExchange
  ) {
    self.exchange = exchange
    self.asyncExchange = asyncExchange
  }

  func request(
    code: String,
    resourceDisplayName: String,
    sshTarget: String
  ) -> M2TTYApprovalOutcome {
    let prompt =
      "PowerVPN M2 one-time approval\n"
      + "Resource: \(resourceDisplayName)\n"
      + "SSH target: \(sshTarget)\n"
      + "This will acquire one authorized resource, run start_connection, perform a fresh SSH proof, stop, and verify cleanup.\n"
      + "Type \(code) exactly and press Return to continue: "
    return request(code: code, prompt: prompt)
  }

  func requestVendorHandoffLaunch(code: String) -> M2TTYApprovalOutcome {
    let prompt =
      "PowerVPN vendor-once handoff approval 1 of 2\n"
      + "This will normally launch the official PowerVPN App so you can log in through its normal UI.\n"
      + "After login, a second approval will ask you to confirm that login21 is connected before handoff.\n"
      + "Type \(code) exactly and press Return to launch the official App: "
    return request(code: code, prompt: prompt)
  }

  func requestVendorHandoffTermination(code: String) async -> M2TTYApprovalOutcome {
    let prompt =
      "PowerVPN vendor-once handoff approval 2 of 2\n"
      + "Confirm that the official PowerVPN App completed a normal login and displays login21 connected.\n"
      + "This will call forceTerminate only on the exact App receiver retained from this launch; it will not use Cmd-Q or request a normal quit.\n"
      + "This approval expires after 10 minutes.\n"
      + "Type \(code) exactly and press Return to perform the handoff: "
    guard Self.validCode(code) else { return .unavailable }
    switch await asyncExchange(prompt, Self.vendorHandoffTimeoutMilliseconds) {
    case .line(let response): return response == code ? .accepted : .denied
    case .unavailable: return .unavailable
    }
  }

  private func request(code: String, prompt: String) -> M2TTYApprovalOutcome {
    guard Self.validCode(code) else { return .unavailable }
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

  private static let vendorHandoffTimeoutMilliseconds: UInt64 = 600_000
  private static let cancellationPollMilliseconds: Int32 = 50

  private static func currentCancellableTerminalExchange(
    _ prompt: String,
    timeoutMilliseconds: UInt64
  ) async -> M2TTYLineRead {
    await runCancellableBlockingExchange {
      blockingCancellableTerminalExchange(
        prompt,
        timeoutMilliseconds: timeoutMilliseconds
      )
    }
  }

  static func runCancellableBlockingExchange(
    _ operation: @escaping @Sendable () -> M2TTYLineRead
  ) async -> M2TTYLineRead {
    let worker = Task.detached(priority: .userInitiated) { operation() }
    return await withTaskCancellationHandler {
      await worker.value
    } onCancel: {
      worker.cancel()
    }
  }

  private static func blockingCancellableTerminalExchange(
    _ prompt: String,
    timeoutMilliseconds: UInt64
  ) -> M2TTYLineRead {
    let descriptor = open("/dev/tty", O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)
    guard descriptor >= 0 else { return .unavailable }
    return cancellableTerminalExchange(
      prompt,
      timeoutMilliseconds: timeoutMilliseconds,
      ownedDescriptor: descriptor
    )
  }

  static func cancellableTerminalExchange(
    _ prompt: String,
    timeoutMilliseconds: UInt64,
    ownedDescriptor descriptor: Int32
  ) -> M2TTYLineRead {
    defer { close(descriptor) }
    guard isatty(descriptor) == 1 else { return .unavailable }
    let flags = fcntl(descriptor, F_GETFL)
    guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
      return .unavailable
    }

    let now = DispatchTime.now().uptimeNanoseconds
    let duration = timeoutMilliseconds.multipliedReportingOverflow(by: 1_000_000)
    guard !duration.overflow, now <= UInt64.max - duration.partialValue else {
      return .unavailable
    }
    let deadline = now + duration.partialValue
    guard cancellableWriteAll(Data(prompt.utf8), to: descriptor, deadline: deadline) else {
      return .unavailable
    }

    var response = [UInt8]()
    response.reserveCapacity(8)
    while response.count <= 8 {
      guard !Task.isCancelled, DispatchTime.now().uptimeNanoseconds < deadline else {
        return .unavailable
      }
      var byte: UInt8 = 0
      let count = read(descriptor, &byte, 1)
      if count == 1 {
        if byte == 0x0A { return .line(String(decoding: response, as: UTF8.self)) }
        response.append(byte)
      } else if count == 0 {
        return .unavailable
      } else if errno == EINTR {
        continue
      } else if errno == EAGAIN || errno == EWOULDBLOCK {
        guard waitForTerminalRetry(deadline: deadline) else { return .unavailable }
      } else {
        return .unavailable
      }
    }
    return .line("")
  }

  private static func cancellableWriteAll(
    _ data: Data,
    to descriptor: Int32,
    deadline: UInt64
  ) -> Bool {
    data.withUnsafeBytes { buffer in
      guard let base = buffer.baseAddress else { return true }
      var written = 0
      while written < buffer.count {
        guard !Task.isCancelled, DispatchTime.now().uptimeNanoseconds < deadline else {
          return false
        }
        let count = write(descriptor, base.advanced(by: written), buffer.count - written)
        if count > 0 {
          written += count
        } else if count < 0, errno == EINTR {
          continue
        } else if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
          guard waitForTerminalRetry(deadline: deadline) else { return false }
        } else {
          return false
        }
      }
      return true
    }
  }

  private static func waitForTerminalRetry(deadline: UInt64) -> Bool {
    guard !Task.isCancelled else { return false }
    let now = DispatchTime.now().uptimeNanoseconds
    guard now < deadline else { return false }
    let remaining = deadline - now
    let interval = min(remaining, UInt64(cancellationPollMilliseconds) * 1_000_000)
    var request = timespec(
      tv_sec: Int(interval / 1_000_000_000),
      tv_nsec: Int(interval % 1_000_000_000)
    )
    while true {
      var remainder = timespec()
      if nanosleep(&request, &remainder) == 0 { break }
      guard errno == EINTR, !Task.isCancelled else { return false }
      request = remainder
    }
    return !Task.isCancelled
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
