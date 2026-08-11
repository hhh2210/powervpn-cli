import Darwin
import Foundation

extension VendorAppOnboardingCursor {
  package func persistDefault() throws {
    try persist(at: Self.defaultPath)
  }

  func persist(
    at path: String,
    afterRename: @Sendable () throws -> Void = {}
  ) throws {
    try validate()
    try VendorAppCursorStateLock.withExclusiveLock(stateFilePath: path) {
      try persistLocked(at: path, afterRename: afterRename)
    }
  }

  package func publishHandoffProof(
    _ proof: VendorAppNonLogoutHandoffProof,
    at path: String = Self.defaultPath
  ) throws -> Self {
    try validate()
    guard handoffProof == nil else { throw VendorAppOnboardingCursorError.invalidCursor }
    let proven = try proving(proof)
    try VendorAppCursorStateLock.withExclusiveLock(stateFilePath: path) {
      guard try Self.load(at: path) == self else {
        throw VendorAppOnboardingCursorError.invalidCursor
      }
      try proven.persistLocked(at: path)
    }
    return proven
  }

  private func persistLocked(
    at path: String,
    afterRename: @Sendable () throws -> Void = {}
  ) throws {
    let destination = URL(fileURLWithPath: path)
    let directory = destination.deletingLastPathComponent()
    var encoded = try JSONEncoder().encode(self)
    defer { encoded.resetBytes(in: 0..<encoded.count) }
    let temporary = directory.appendingPathComponent(
      ".cursor-\(UUID().uuidString).tmp"
    ).path
    let descriptor = temporary.withCString {
      open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)
    }
    guard descriptor >= 0 else { throw VendorAppOnboardingCursorError.stateUnavailable }
    var installed = false
    defer {
      close(descriptor)
      if !installed { temporary.withCString { _ = unlink($0) } }
    }
    guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0,
      Self.writeAll(encoded, to: descriptor),
      fsync(descriptor) == 0,
      temporary.withCString({ source in
        path.withCString { rename(source, $0) }
      }) == 0
    else { throw VendorAppOnboardingCursorError.stateUnavailable }
    installed = true
    do {
      try afterRename()
      try Self.validateStateFile(at: path, descriptor: descriptor)
      guard Self.syncDirectory(directory.path) else {
        throw VendorAppOnboardingCursorError.stateUnavailable
      }
    } catch {
      Self.rollbackInstalledStateFile(
        at: path,
        descriptor: descriptor,
        directory: directory.path
      )
      throw error
    }
  }

  private static func validateStateFile(at path: String, descriptor: Int32) throws {
    var descriptorState = stat()
    var pathState = stat()
    guard fstat(descriptor, &descriptorState) == 0,
      path.withCString({ lstat($0, &pathState) }) == 0,
      exactMetadata(descriptorState, pathState),
      descriptorState.st_mode & S_IFMT == S_IFREG,
      descriptorState.st_uid == getuid(),
      descriptorState.st_mode & mode_t(0o7777) == S_IRUSR | S_IWUSR,
      descriptorState.st_nlink == 1,
      VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor),
      (1...4_096).contains(descriptorState.st_size)
    else { throw VendorAppOnboardingCursorError.stateUnavailable }
  }

  private static func rollbackInstalledStateFile(
    at path: String,
    descriptor: Int32,
    directory: String
  ) {
    var descriptorState = stat()
    var pathState = stat()
    let installedPathMatches =
      fstat(descriptor, &descriptorState) == 0
      && path.withCString({ lstat($0, &pathState) }) == 0
      && descriptorState.st_dev == pathState.st_dev
      && descriptorState.st_ino == pathState.st_ino
    if installedPathMatches, path.withCString({ unlink($0) }) != 0 {
      _ = ftruncate(descriptor, 0)
      _ = fsync(descriptor)
    } else if !installedPathMatches {
      _ = path.withCString { unlink($0) }
    }
    _ = syncDirectory(directory)
  }

  private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
    data.withUnsafeBytes { bytes in
      var offset = 0
      while offset < bytes.count {
        let count = write(descriptor, bytes.baseAddress! + offset, bytes.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { return false }
        offset += count
      }
      return true
    }
  }
}
