import Darwin
import Foundation

extension VendorAppOnboardingCursor {
  /// Atomically claims this cursor for one mutating M2 attempt.
  package func consumeDefault() throws {
    try consume(at: Self.defaultPath)
  }

  func consume(
    at path: String,
    beforeUnlink: @Sendable () -> Void = {}
  ) throws {
    try validate()
    try VendorAppCursorStateLock.withExclusiveLock(stateFilePath: path) {
      try consumeLocked(at: path, beforeUnlink: beforeUnlink)
    }
  }

  private func consumeLocked(
    at path: String,
    beforeUnlink: @Sendable () -> Void
  ) throws {
    let descriptor = path.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) }
    guard descriptor >= 0 else { throw VendorAppOnboardingCursorError.stateUnavailable }
    defer { close(descriptor) }
    var descriptorState = stat()
    var pathState = stat()
    guard fstat(descriptor, &descriptorState) == 0,
      path.withCString({ lstat($0, &pathState) }) == 0,
      Self.exactMetadata(descriptorState, pathState),
      descriptorState.st_mode & S_IFMT == S_IFREG,
      descriptorState.st_uid == getuid(),
      descriptorState.st_mode & mode_t(0o7777) == S_IRUSR | S_IWUSR,
      descriptorState.st_nlink == 1,
      VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor),
      (1...4_096).contains(descriptorState.st_size)
    else { throw VendorAppOnboardingCursorError.invalidCursor }

    var bytes = Data(count: Int(descriptorState.st_size))
    defer { bytes.resetBytes(in: 0..<bytes.count) }
    let count = bytes.count
    let readCount = bytes.withUnsafeMutableBytes { buffer in
      var total = 0
      while total < count {
        let result = pread(descriptor, buffer.baseAddress! + total, count - total, off_t(total))
        if result < 0 && errno == EINTR { continue }
        guard result > 0 else { return -1 }
        total += result
      }
      return total
    }
    guard readCount == count,
      let observed = try? JSONDecoder().decode(Self.self, from: bytes),
      observed == self
    else { throw VendorAppOnboardingCursorError.invalidCursor }
    var afterRead = stat()
    var pathAfterRead = stat()
    guard fstat(descriptor, &afterRead) == 0,
      path.withCString({ lstat($0, &pathAfterRead) }) == 0,
      Self.exactMetadata(descriptorState, afterRead),
      Self.exactMetadata(descriptorState, pathAfterRead)
    else { throw VendorAppOnboardingCursorError.invalidCursor }
    beforeUnlink()
    var pathBeforeUnlink = stat()
    guard path.withCString({ lstat($0, &pathBeforeUnlink) }) == 0,
      Self.exactMetadata(descriptorState, pathBeforeUnlink),
      path.withCString({ unlink($0) }) == 0
    else { throw VendorAppOnboardingCursorError.invalidCursor }
    let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
    guard Self.syncDirectory(directory) else {
      throw VendorAppOnboardingCursorError.stateUnavailable
    }
  }
}
