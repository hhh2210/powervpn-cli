import Darwin

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

public struct DarwinSecureTerminalCredentialReader: SecureTerminalCredentialReading {
  static let bufferCapacity = 4_096
  private static let readFlags = RPP_ECHO_OFF | RPP_REQUIRE_TTY

  private let driver: any ReadPassphraseDriving
  private let bufferEraseObserver:
    (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)?
  private let secureEraseObserver:
    (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)?

  public init() {
    driver = DarwinReadPassphraseDriver()
    bufferEraseObserver = nil
    secureEraseObserver = nil
  }

  init(
    driver: any ReadPassphraseDriving,
    bufferEraseObserver:
      (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)? = nil,
    secureEraseObserver:
      (@Sendable (SecureTerminalCredentialPrompt, UnsafeRawBufferPointer) -> Void)? = nil
  ) {
    self.driver = driver
    self.bufferEraseObserver = bufferEraseObserver
    self.secureEraseObserver = secureEraseObserver
  }

  public func readCredentials() throws -> PortalCredentials {
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

    switch driver.read(
      prompt: prompt,
      into: buffer,
      capacity: Self.bufferCapacity,
      flags: Self.readFlags
    ) {
    case .success:
      break
    case .failure(let errorNumber):
      throw errorNumber == EINTR ? SecureTerminalCredentialError.cancelled : .unavailable
    }

    let count = strnlen(buffer, Self.bufferCapacity)
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

enum ReadPassphraseDriverResult: Sendable {
  case success
  case failure(Int32)
}

protocol ReadPassphraseDriving: Sendable {
  func read(
    prompt: SecureTerminalCredentialPrompt,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int,
    flags: Int32
  ) -> ReadPassphraseDriverResult
}

private struct DarwinReadPassphraseDriver: ReadPassphraseDriving {
  func read(
    prompt: SecureTerminalCredentialPrompt,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int,
    flags: Int32
  ) -> ReadPassphraseDriverResult {
    errno = 0
    let result = prompt.rawValue.withCString {
      readpassphrase($0, buffer, capacity, flags)
    }
    return result == nil ? .failure(errno) : .success
  }
}
