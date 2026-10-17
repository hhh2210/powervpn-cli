import Darwin
import Foundation

@_silgen_name("flock")
private func userProductRecoveryFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

extension UserProductSessionStateStore {
  func recoveryArchivePath(sessionID: String) -> String {
    precondition(UUID(uuidString: sessionID) != nil)
    return directory.appendingPathComponent("recovery-\(sessionID.lowercased()).json").path
  }

  func loadRecoveryArchive(sessionID: String) throws -> UserProductRecoveryArchive? {
    guard UUID(uuidString: sessionID) != nil else {
      throw UserProductSessionStoreError.invalidState
    }
    return try withRecoveryArchiveLock {
      try loadRecoveryArchiveUnlocked(sessionID: sessionID)
    }
  }

  func saveRecoveryArchive(_ archive: UserProductRecoveryArchive) throws {
    guard archive.valid else { throw UserProductSessionStoreError.invalidState }
    try withRecoveryArchiveLock { try saveRecoveryArchiveUnlocked(archive) }
  }

  @discardableResult
  func removeRecoveryArchive(expected: UserProductRecoveryArchive) throws -> Bool {
    try withRecoveryArchiveLock {
      guard
        let current = try loadRecoveryArchiveUnlocked(sessionID: expected.originalSessionID),
        current == expected
      else {
        return false
      }
      guard
        Darwin.unlink(recoveryArchivePath(sessionID: expected.originalSessionID)) == 0,
        syncRecoveryDirectory()
      else {
        throw UserProductSessionStoreError.unsafeStateFile
      }
      return true
    }
  }

  private func withRecoveryArchiveLock<T>(_ body: () throws -> T) throws -> T {
    try ensureRecoveryDirectory()
    let path = directory.appendingPathComponent("recovery-state.lock").path
    let descriptor = Darwin.open(
      path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
    guard descriptor >= 0 else { throw UserProductSessionStoreError.unsafeStateFile }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFREG,
      fchmod(descriptor, 0o600) == 0,
      userProductRecoveryFlock(descriptor, LOCK_EX) == 0
    else {
      Darwin.close(descriptor)
      throw UserProductSessionStoreError.unsafeStateFile
    }
    defer {
      _ = userProductRecoveryFlock(descriptor, LOCK_UN)
      _ = Darwin.close(descriptor)
    }
    return try body()
  }

  private func ensureRecoveryDirectory() throws {
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
      metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFDIR,
      chmod(directory.path, 0o700) == 0
    else { throw UserProductSessionStoreError.unsafeStateDirectory }
  }

  private func loadRecoveryArchiveUnlocked(
    sessionID: String
  ) throws -> UserProductRecoveryArchive? {
    let path = recoveryArchivePath(sessionID: sessionID)
    var link = stat()
    guard lstat(path, &link) == 0 else {
      if errno == ENOENT { return nil }
      throw UserProductSessionStoreError.unsafeStateFile
    }
    guard link.st_mode & S_IFMT == S_IFREG else {
      throw UserProductSessionStoreError.unsafeStateFile
    }
    let descriptor = Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw UserProductSessionStoreError.unsafeStateFile }
    defer { Darwin.close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFREG,
      metadata.st_mode & 0o777 == 0o600,
      metadata.st_size > 0, metadata.st_size <= Self.maximumStateBytes,
      metadata.st_dev == link.st_dev, metadata.st_ino == link.st_ino
    else { throw UserProductSessionStoreError.unsafeStateFile }
    var data = Data(count: Int(metadata.st_size))
    let expected = data.count
    let actual = data.withUnsafeMutableBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return -1 }
      var offset = 0
      while offset < expected {
        let count = Darwin.read(descriptor, base + offset, expected - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { return -1 }
        offset += count
      }
      return offset
    }
    guard actual == expected,
      let archive = try? JSONDecoder().decode(UserProductRecoveryArchive.self, from: data),
      archive.valid
    else { throw UserProductSessionStoreError.invalidState }
    return archive
  }

  private func saveRecoveryArchiveUnlocked(_ archive: UserProductRecoveryArchive) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(archive)
    guard !data.isEmpty, data.count <= Self.maximumStateBytes else {
      throw UserProductSessionStoreError.invalidState
    }
    let temporary = directory.appendingPathComponent(
      ".recovery.\(UUID().uuidString).tmp"
    ).path
    let descriptor = Darwin.open(
      temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      mode_t(0o600)
    )
    guard descriptor >= 0 else { throw UserProductSessionStoreError.unsafeStateFile }
    var succeeded = false
    defer {
      _ = Darwin.close(descriptor)
      if !succeeded { _ = Darwin.unlink(temporary) }
    }
    let written = data.withUnsafeBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return -1 }
      var offset = 0
      while offset < buffer.count {
        let count = Darwin.write(descriptor, base + offset, buffer.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { return -1 }
        offset += count
      }
      return offset
    }
    guard written == data.count, fsync(descriptor) == 0,
      rename(temporary, recoveryArchivePath(sessionID: archive.originalSessionID)) == 0,
      syncRecoveryDirectory()
    else { throw UserProductSessionStoreError.unsafeStateFile }
    succeeded = true
  }

  private func syncRecoveryDirectory() -> Bool {
    let descriptor = Darwin.open(directory.path, O_RDONLY | O_CLOEXEC | O_DIRECTORY)
    guard descriptor >= 0 else { return false }
    defer { Darwin.close(descriptor) }
    return fsync(descriptor) == 0
  }
}
