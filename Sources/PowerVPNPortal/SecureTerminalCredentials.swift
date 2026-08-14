import Darwin
import Dispatch

public enum SecureTerminalCredentialPrompt: String, CaseIterable, Sendable {
  case username = "PowerVPN Username: "
  case password = "PowerVPN Password: "
}

public enum SecureTerminalCredentialError: Error, Equatable, Sendable {
  case cancelled
  case unavailable
  case empty(SecureTerminalCredentialPrompt)
  case inputTooLong(SecureTerminalCredentialPrompt)
}

public final class PortalCredentials: @unchecked Sendable {
  private let username: SecureBytes
  private let password: SecureBytes

  init(username: SecureBytes, password: SecureBytes) {
    self.username = username
    self.password = password
  }

  public func erase() {
    username.erase()
    password.erase()
  }

  deinit {
    erase()
  }

  var usernameByteCount: Int { username.count }
  var passwordByteCount: Int { password.count }

  func withUsernameBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try username.withUnsafeBytes(body)
  }

  func withPasswordBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try password.withUnsafeBytes(body)
  }
}

public protocol SecureTerminalCredentialReading: Sendable {
  func readCredentials() throws -> PortalCredentials
}
final class TerminalCredentialTransactionGate: @unchecked Sendable {
  static let controllingTTY = TerminalCredentialTransactionGate()
  static let cancellationCheckMilliseconds = 50

  private let semaphore = DispatchSemaphore(value: 1)
  private let waitObserver: (@Sendable () -> Void)?
  private let acquisitionObserver: (@Sendable () -> Void)?

  init(
    waitObserver: (@Sendable () -> Void)? = nil,
    acquisitionObserver: (@Sendable () -> Void)? = nil
  ) {
    self.waitObserver = waitObserver
    self.acquisitionObserver = acquisitionObserver
  }

  func acquire() -> Bool {
    while true {
      guard !Task.isCancelled else { return false }
      let result = semaphore.wait(
        timeout: .now() + .milliseconds(Self.cancellationCheckMilliseconds)
      )
      guard result == .success else {
        waitObserver?()
        continue
      }
      acquisitionObserver?()
      guard !Task.isCancelled else {
        semaphore.signal()
        return false
      }
      return true
    }
  }

  func release() {
    semaphore.signal()
  }
}

public struct DarwinSecureTerminalCredentialReader: SecureTerminalCredentialReading {
  static let bufferCapacity = 4_096

  private let driver: any TerminalCredentialDriving
  private let transactionGate: TerminalCredentialTransactionGate
  private let bufferEraseObserver:
    (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)?
  private let secureEraseObserver:
    (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)?

  public init() {
    driver = DarwinTerminalCredentialDriver()
    transactionGate = .controllingTTY
    bufferEraseObserver = nil
    secureEraseObserver = nil
  }

  init(
    driver: any TerminalCredentialDriving,
    transactionGate: TerminalCredentialTransactionGate = .controllingTTY,
    bufferEraseObserver:
      (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)? = nil,
    secureEraseObserver:
      (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)? = nil
  ) {
    self.driver = driver
    self.transactionGate = transactionGate
    self.bufferEraseObserver = bufferEraseObserver
    self.secureEraseObserver = secureEraseObserver
  }

  public func readCredentials() throws -> PortalCredentials {
    guard transactionGate.acquire() else {
      throw SecureTerminalCredentialError.cancelled
    }
    defer { transactionGate.release() }
    guard !Task.isCancelled else {
      throw SecureTerminalCredentialError.cancelled
    }
    let username: SecureBytes
    do {
      username = try read(.username)
    } catch {
      throw normalize(error)
    }
    do {
      let password = try read(.password)
      return PortalCredentials(username: username, password: password)
    } catch {
      username.erase()
      throw normalize(error)
    }
  }

  private func read(_ prompt: SecureTerminalCredentialPrompt) throws -> SecureBytes {
    let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: Self.bufferCapacity)
    buffer.initialize(repeating: 0, count: Self.bufferCapacity)
    defer {
      _ = memset_s(buffer, Self.bufferCapacity, 0, Self.bufferCapacity)
      bufferEraseObserver?(
        prompt,
        UnsafeRawBufferPointer(start: buffer, count: Self.bufferCapacity)
      )
      buffer.deinitialize(count: Self.bufferCapacity)
      buffer.deallocate()
    }

    let count: Int
    switch driver.read(
      prompt: prompt,
      into: buffer,
      capacity: Self.bufferCapacity,
      disableEcho: true
    ) {
    case .success(let byteCount):
      count = byteCount
    case .cancelled:
      throw SecureTerminalCredentialError.cancelled
    case .failure:
      throw SecureTerminalCredentialError.unavailable
    }

    guard count > 0 else { throw SecureTerminalCredentialError.empty(prompt) }
    guard count < Self.bufferCapacity - 1 else {
      throw SecureTerminalCredentialError.inputTooLong(prompt)
    }
    return try SecureBytes(
      copying: UnsafeRawBufferPointer(start: buffer, count: count),
      eraseObserver: { [secureEraseObserver] bytes in
        secureEraseObserver?(prompt, bytes)
      }
    )
  }

  private func normalize(_ error: Error) -> SecureTerminalCredentialError {
    (error as? SecureTerminalCredentialError) ?? .unavailable
  }
}
