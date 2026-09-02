import Darwin
import Foundation
import PowerVPNProduct

@_silgen_name("flock")
private func userProductFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

enum UserProductSessionPhase: String, Codable, Equatable, Sendable {
  case connecting
  case connected
  case disconnecting
  case disconnected
  case failed
}

struct UserProductSessionState: Codable, Equatable, Sendable {
  let schemaVersion: Int
  let sessionID: String
  let target: String
  let controlPath: String
  var phase: UserProductSessionPhase
  var ownerPID: Int?
  var cleanupVerified: Bool?
  var failure: String?

  init(
    sessionID: String,
    target: String,
    controlPath: String,
    phase: UserProductSessionPhase,
    ownerPID: Int? = nil,
    cleanupVerified: Bool? = nil,
    failure: String? = nil
  ) {
    schemaVersion = 1
    self.sessionID = sessionID
    self.target = target
    self.controlPath = controlPath
    self.phase = phase
    self.ownerPID = ownerPID
    self.cleanupVerified = cleanupVerified
    self.failure = failure
  }

  var terminal: Bool { phase == .disconnected || phase == .failed }

  var valid: Bool {
    schemaVersion == 1
      && UUID(uuidString: sessionID)?.uuidString.lowercased() == sessionID.lowercased()
      && ProductM2SSHTarget(rawValue: target) != nil
      && controlPath.hasPrefix("/")
      && !controlPath.contains("\0")
      && !controlPath.contains("\n")
      && ownerPID.map { $0 > 0 } ?? true
  }
}

enum UserProductSessionStoreError: Error, Equatable {
  case unsafeStateDirectory
  case unsafeStateFile
  case invalidState
  case busy
}

final class UserProductSessionCommandLock {
  private let descriptor: Int32

  init(descriptor: Int32) { self.descriptor = descriptor }

  deinit {
    _ = userProductFlock(descriptor, LOCK_UN)
    _ = Darwin.close(descriptor)
  }
}

struct UserProductSessionStateStore: Sendable {
  static let maximumStateBytes = 16 * 1_024

  let directory: URL

  init(
    directory: URL = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".local", isDirectory: true)
      .appendingPathComponent("state", isDirectory: true)
      .appendingPathComponent("powervpn", isDirectory: true)
  ) {
    self.directory = directory
  }

  var statePath: String {
    directory.appendingPathComponent("session.json").path
  }

  func acquireCommandLock() throws -> UserProductSessionCommandLock {
    try ensureDirectory()
    let descriptor = try openLock(named: "session-command.lock")
    guard userProductFlock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      Darwin.close(descriptor)
      throw UserProductSessionStoreError.busy
    }
    return UserProductSessionCommandLock(descriptor: descriptor)
  }

  func load() throws -> UserProductSessionState? {
    try withStateLock { try loadUnlocked() }
  }

  func save(_ state: UserProductSessionState) throws {
    guard state.valid else { throw UserProductSessionStoreError.invalidState }
    try withStateLock { try saveUnlocked(state) }
  }

  @discardableResult
  func update(
    sessionID: String,
    _ transform: (inout UserProductSessionState) -> Void
  ) throws -> Bool {
    try withStateLock {
      guard var state = try loadUnlocked(), state.sessionID == sessionID else { return false }
      transform(&state)
      guard state.valid else { throw UserProductSessionStoreError.invalidState }
      try saveUnlocked(state)
      return true
    }
  }

  @discardableResult
  func remove(sessionID: String? = nil) throws -> Bool {
    try withStateLock {
      if let sessionID {
        guard let state = try loadUnlocked(), state.sessionID == sessionID else { return false }
      }
      let path = statePath
      if Darwin.unlink(path) == 0 { return true }
      if errno == ENOENT { return false }
      throw UserProductSessionStoreError.unsafeStateFile
    }
  }

  private func withStateLock<T>(_ body: () throws -> T) throws -> T {
    try ensureDirectory()
    let descriptor = try openLock(named: "session-state.lock")
    guard userProductFlock(descriptor, LOCK_EX) == 0 else {
      Darwin.close(descriptor)
      throw UserProductSessionStoreError.unsafeStateFile
    }
    defer {
      _ = userProductFlock(descriptor, LOCK_UN)
      _ = Darwin.close(descriptor)
    }
    return try body()
  }

  private func ensureDirectory() throws {
    do {
      try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } catch {
      throw UserProductSessionStoreError.unsafeStateDirectory
    }
    var metadata = stat()
    guard lstat(directory.path, &metadata) == 0,
      metadata.st_uid == getuid(),
      metadata.st_mode & S_IFMT == S_IFDIR,
      chmod(directory.path, 0o700) == 0
    else { throw UserProductSessionStoreError.unsafeStateDirectory }
  }

  private func openLock(named name: String) throws -> Int32 {
    let path = directory.appendingPathComponent(name).path
    let descriptor = Darwin.open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { throw UserProductSessionStoreError.unsafeStateFile }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      metadata.st_uid == getuid(),
      metadata.st_mode & S_IFMT == S_IFREG,
      fchmod(descriptor, 0o600) == 0
    else {
      Darwin.close(descriptor)
      throw UserProductSessionStoreError.unsafeStateFile
    }
    return descriptor
  }

  private func loadUnlocked() throws -> UserProductSessionState? {
    let path = statePath
    var linkMetadata = stat()
    guard lstat(path, &linkMetadata) == 0 else {
      if errno == ENOENT { return nil }
      throw UserProductSessionStoreError.unsafeStateFile
    }
    guard linkMetadata.st_mode & S_IFMT == S_IFREG else {
      throw UserProductSessionStoreError.unsafeStateFile
    }
    let descriptor = Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw UserProductSessionStoreError.unsafeStateFile }
    defer { Darwin.close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      metadata.st_uid == getuid(),
      metadata.st_mode & S_IFMT == S_IFREG,
      metadata.st_mode & 0o777 == 0o600,
      metadata.st_size > 0,
      metadata.st_size <= Self.maximumStateBytes
    else { throw UserProductSessionStoreError.unsafeStateFile }
    var data = Data(count: Int(metadata.st_size))
    let expected = data.count
    let actual = data.withUnsafeMutableBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return -1 }
      var offset = 0
      while offset < expected {
        let count = Darwin.read(descriptor, base + offset, expected - offset)
        if count <= 0 { return count == 0 ? offset : -1 }
        offset += count
      }
      return offset
    }
    guard actual == expected,
      let state = try? JSONDecoder().decode(UserProductSessionState.self, from: data),
      state.valid
    else { throw UserProductSessionStoreError.invalidState }
    return state
  }

  private func saveUnlocked(_ state: UserProductSessionState) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(state)
    guard !data.isEmpty, data.count <= Self.maximumStateBytes else {
      throw UserProductSessionStoreError.invalidState
    }
    let temporary = directory.appendingPathComponent(".session.\(UUID().uuidString).tmp").path
    let descriptor = Darwin.open(
      temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard descriptor >= 0 else { throw UserProductSessionStoreError.unsafeStateFile }
    var succeeded = false
    defer {
      Darwin.close(descriptor)
      if !succeeded { Darwin.unlink(temporary) }
    }
    let written = data.withUnsafeBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return -1 }
      var offset = 0
      while offset < buffer.count {
        let count = Darwin.write(descriptor, base + offset, buffer.count - offset)
        if count <= 0 { return -1 }
        offset += count
      }
      return offset
    }
    guard written == data.count, fsync(descriptor) == 0,
      rename(temporary, statePath) == 0
    else { throw UserProductSessionStoreError.unsafeStateFile }
    succeeded = true
  }
}
