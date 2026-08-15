import Darwin
import Foundation

/// Fail-closed classification of a rejected credential file. Value-free: no
/// file bytes, values, paths, or sizes are representable here.
public enum EnvFileCredentialError: Error, Equatable, Sendable {
  /// The path exists but is not a regular file (symlinks are rejected too).
  case notARegularFile
  /// The file's mode grants group or other any access (`st_mode & 0o077 != 0`).
  case insecurePermissions
  /// The file's contents deviate from the strict two-line KEY=VALUE format,
  /// or the override environment variable is not an absolute path.
  case malformed
  /// The file (or one of its values) exceeds the fixed size bounds.
  case tooLarge
  /// The file could not be opened, read, or stat'ed.
  case unreadable
}

/// Reads portal credentials from a protected env-style file.
///
/// The file must be a regular file (symlinks rejected; type and mode are
/// re-verified on the opened descriptor), owned-readable/writable only
/// (`st_mode & 0o077 == 0`, i.e. 0600), and contain exactly two KEY=VALUE
/// lines — `PORTAL_USERNAME` and `PORTAL_PASSWORD`, each exactly once, in
/// either order, with non-empty values — plus at most one trailing newline,
/// no CR, no comments, and no other keys. Any deviation throws
/// `EnvFileCredentialError`; callers must fail closed and must not silently
/// fall back to interactive TTY input.
public struct EnvFileCredentialReader: SecureTerminalCredentialReading {
  /// Environment variable overriding the default path. Absolute paths only.
  public static let overrideEnvironmentVariable = "POWERVPN_PORTAL_CREDENTIALS"

  static let defaultPath = "~/.config/powervpn/credentials.env"
  static let usernameKey = Array("PORTAL_USERNAME".utf8)
  static let passwordKey = Array("PORTAL_PASSWORD".utf8)
  static let maximumFileBytes = 8_192
  static let maximumValueBytes = 4_095

  private let path: String

  /// Creates a reader for `path`, or for the default path when omitted.
  /// Tilde expansion is applied to the default path only; explicit paths are
  /// used verbatim.
  public init(path: String? = nil) {
    let raw = path ?? Self.defaultPath
    self.path =
      raw == Self.defaultPath
      ? (raw as NSString).expandingTildeInPath
      : raw
  }

  public func readCredentials() throws -> PortalCredentials {
    let descriptor = try openCredentialFile()
    defer { close(descriptor) }

    let stat = try statCredentialFile(descriptor)
    guard stat.st_size >= 0, stat.st_size <= Int32(Self.maximumFileBytes) else {
      throw EnvFileCredentialError.tooLarge
    }
    let count = Int(stat.st_size)
    if count == 0 { throw EnvFileCredentialError.malformed }

    let buffer = UnsafeMutableRawPointer.allocate(
      byteCount: count, alignment: MemoryLayout<UInt8>.alignment)
    buffer.initializeMemory(as: UInt8.self, repeating: 0, count: count)
    defer {
      _ = memset_s(buffer, count, 0, count)
      buffer.deallocate()
    }

    let read = try readCredentialFile(descriptor, into: buffer, count: count)
    let bytes = UnsafeRawBufferPointer(start: buffer, count: read)
    let (usernameRange, passwordRange) = try Self.parse(bytes)

    let username = try SecureBytes(
      copying: UnsafeRawBufferPointer(rebasing: bytes[usernameRange]))
    do {
      let password = try SecureBytes(
        copying: UnsafeRawBufferPointer(rebasing: bytes[passwordRange]))
      return PortalCredentials(username: username, password: password)
    } catch {
      username.erase()
      throw error
    }
  }

  // MARK: - Current-machine override resolution

  enum OverrideResolution: Equatable, Sendable {
    case defaultPath
    case override(String)
    case invalidOverride
  }

  static func resolveCurrentMachineOverride(
    environment: [String: String] = ProcessInfo.processInfo.environment
  ) -> OverrideResolution {
    guard let override = environment[Self.overrideEnvironmentVariable] else {
      return .defaultPath
    }
    guard !override.isEmpty, override.hasPrefix("/") else { return .invalidOverride }
    return .override(override)
  }

  static func currentMachinePath(
    environment: [String: String] = ProcessInfo.processInfo.environment
  ) throws -> String {
    switch resolveCurrentMachineOverride(environment: environment) {
    case .defaultPath:
      return (defaultPath as NSString).expandingTildeInPath
    case .override(let path):
      return path
    case .invalidOverride:
      throw EnvFileCredentialError.malformed
    }
  }

  /// Whether a current-machine credential file is present. An invalid
  /// (non-absolute) override counts as present so that the run fails closed
  /// instead of silently prompting on the TTY.
  static func currentMachineCredentialFileExists(
    environment: [String: String] = ProcessInfo.processInfo.environment,
    fileExists: @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
  ) -> Bool {
    do {
      return fileExists(try currentMachinePath(environment: environment))
    } catch {
      return true
    }
  }
}

/// The single current-machine credential seam: a protected credentials file,
/// when present, takes precedence over interactive TTY input. Permission or
/// format failures in the file surface as reader errors — the runtime maps
/// them to the `credential_input_rejected` closed report — and only the
/// file's absence selects the existing TTY reader. A present-but-rejected
/// file never silently falls back to the TTY.
struct PortalCredentialPrecedenceReader: SecureTerminalCredentialReading {
  let credentialFileExists: @Sendable () -> Bool
  let credentialFileReader: any SecureTerminalCredentialReading
  let terminalReader: any SecureTerminalCredentialReading

  init(
    credentialFileExists: @escaping @Sendable () -> Bool,
    credentialFileReader: any SecureTerminalCredentialReading,
    terminalReader: any SecureTerminalCredentialReading
  ) {
    self.credentialFileExists = credentialFileExists
    self.credentialFileReader = credentialFileReader
    self.terminalReader = terminalReader
  }

  /// Current-machine composition: `POWERVPN_PORTAL_CREDENTIALS` override
  /// resolution, default-path expansion, and TTY fallback in one injectable
  /// seam. An invalid override pins a reader that always throws, so the run
  /// fails closed with `credential_input_rejected`.
  static func currentMachine(
    environment: [String: String] = ProcessInfo.processInfo.environment,
    fileExists: @escaping @Sendable (String) -> Bool = {
      FileManager.default.fileExists(atPath: $0)
    },
    envFileReader: @escaping @Sendable (String) -> any SecureTerminalCredentialReading = {
      EnvFileCredentialReader(path: $0)
    },
    terminalReader: any SecureTerminalCredentialReading = DarwinSecureTerminalCredentialReader()
  ) -> PortalCredentialPrecedenceReader {
    switch EnvFileCredentialReader.resolveCurrentMachineOverride(environment: environment) {
    case .defaultPath:
      let path = (EnvFileCredentialReader.defaultPath as NSString).expandingTildeInPath
      return PortalCredentialPrecedenceReader(
        credentialFileExists: { fileExists(path) },
        credentialFileReader: envFileReader(path),
        terminalReader: terminalReader
      )
    case .override(let path):
      return PortalCredentialPrecedenceReader(
        credentialFileExists: { fileExists(path) },
        credentialFileReader: envFileReader(path),
        terminalReader: terminalReader
      )
    case .invalidOverride:
      return PortalCredentialPrecedenceReader(
        credentialFileExists: { true },
        credentialFileReader: InvalidOverrideCredentialReader(),
        terminalReader: terminalReader
      )
    }
  }

  func readCredentials() throws -> PortalCredentials {
    if credentialFileExists() {
      return try credentialFileReader.readCredentials()
    }
    return try terminalReader.readCredentials()
  }
}

private struct InvalidOverrideCredentialReader: SecureTerminalCredentialReading {
  func readCredentials() throws -> PortalCredentials {
    throw EnvFileCredentialError.malformed
  }
}

extension EnvFileCredentialReader {
  fileprivate func openCredentialFile() throws -> Int32 {
    // Reject symlinks and non-regular files outright before opening.
    var linkStat = stat()
    guard lstat(path, &linkStat) == 0 else {
      throw EnvFileCredentialError.unreadable
    }
    guard linkStat.st_mode & S_IFMT == S_IFREG else {
      throw EnvFileCredentialError.notARegularFile
    }

    let descriptor = open(path, O_RDONLY | O_CLOEXEC)
    guard descriptor >= 0 else { throw EnvFileCredentialError.unreadable }
    return descriptor
  }

  fileprivate func statCredentialFile(_ descriptor: Int32) throws -> stat {
    var openStat = stat()
    guard fstat(descriptor, &openStat) == 0 else {
      throw EnvFileCredentialError.unreadable
    }
    guard openStat.st_mode & S_IFMT == S_IFREG else {
      throw EnvFileCredentialError.notARegularFile
    }
    guard openStat.st_mode & 0o077 == 0 else {
      throw EnvFileCredentialError.insecurePermissions
    }
    return openStat
  }

  fileprivate func readCredentialFile(
    _ descriptor: Int32,
    into buffer: UnsafeMutableRawPointer,
    count: Int
  ) throws -> Int {
    var total = 0
    while total < count {
      let chunk = read(descriptor, buffer + total, count - total)
      if chunk < 0 { throw EnvFileCredentialError.unreadable }
      if chunk == 0 { break }
      total += chunk
    }
    guard total > 0 else { throw EnvFileCredentialError.malformed }
    return total
  }
}

extension EnvFileCredentialReader {
  /// Parses `bytes` as the strict two-line KEY=VALUE format and returns the
  /// value ranges for `PORTAL_USERNAME` and `PORTAL_PASSWORD`. No secret
  /// material is copied; only ranges into the caller's buffer are returned.
  static func parse(
    _ bytes: UnsafeRawBufferPointer
  ) throws -> (username: Range<Int>, password: Range<Int>) {
    guard !bytes.contains(0x0D) else { throw EnvFileCredentialError.malformed }

    var contentEnd = bytes.count
    if contentEnd > 0, bytes[contentEnd - 1] == 0x0A {
      contentEnd -= 1
    }
    // A newline still at the end of content means a blank final line
    // (e.g. "K=V\n\n"); an empty content means an empty or newline-only file.
    guard contentEnd > 0, bytes[contentEnd - 1] != 0x0A else {
      throw EnvFileCredentialError.malformed
    }

    var usernameRange: Range<Int>?
    var passwordRange: Range<Int>?

    var lineStart = 0
    while lineStart < contentEnd {
      var lineEnd = lineStart
      while lineEnd < contentEnd, bytes[lineEnd] != 0x0A {
        lineEnd += 1
      }
      guard lineEnd > lineStart else { throw EnvFileCredentialError.malformed }
      let parsed = try parseLine(
        UnsafeRawBufferPointer(rebasing: bytes[lineStart..<lineEnd]),
        at: lineStart)

      if parsed.key == usernameKey {
        guard usernameRange == nil else { throw EnvFileCredentialError.malformed }
        usernameRange = parsed.value
      } else {
        guard passwordRange == nil else { throw EnvFileCredentialError.malformed }
        passwordRange = parsed.value
      }
      lineStart = lineEnd + 1
    }

    guard let username = usernameRange, let password = passwordRange else {
      throw EnvFileCredentialError.malformed
    }
    return (username, password)
  }

  private static func parseLine(
    _ line: UnsafeRawBufferPointer,
    at offset: Int
  ) throws -> (key: [UInt8], value: Range<Int>) {
    guard let separator = line.firstIndex(of: UInt8(ascii: "=")) else {
      throw EnvFileCredentialError.malformed
    }
    let key = Array(line[..<separator])
    guard key == usernameKey || key == passwordKey else {
      throw EnvFileCredentialError.malformed
    }
    let valueStart = offset + separator + 1
    let valueEnd = offset + line.count
    guard valueStart < valueEnd else { throw EnvFileCredentialError.malformed }
    guard valueEnd - valueStart <= maximumValueBytes else {
      throw EnvFileCredentialError.tooLarge
    }
    return (key, valueStart..<valueEnd)
  }
}
