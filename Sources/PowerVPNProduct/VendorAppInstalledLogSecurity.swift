import Darwin
import Foundation

enum VendorAppInstalledLogSecurity {
  static func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
    errno = 0
    guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      return errno == ENOENT
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    // Darwin returns a non-nil ACL only when extended ACL state exists. Reject
    // that state without relying on the platform-specific acl_get_entry result.
    return false
  }

  static func endsAtLineBoundary(_ descriptor: Int32, size: off_t) -> Bool {
    guard size >= 0 else { return false }
    guard size > 0 else { return true }
    var byte: UInt8 = 0
    return pread(descriptor, &byte, 1, size - 1) == 1 && byte == 0x0A
  }
}

enum VendorAppCursorStateLock {
  static let fileName = "vendor-onboarding-cursor.lock"
  private static let permissionMask = mode_t(0o7777)

  static func withExclusiveLock<Result>(
    stateFilePath: String,
    _ body: () throws -> Result
  ) throws -> Result {
    let directory = URL(fileURLWithPath: stateFilePath).deletingLastPathComponent().path
    try VendorAppOnboardingCursor.ensureStateDirectory(directory)
    let lockPath = URL(fileURLWithPath: directory)
      .appendingPathComponent(fileName, isDirectory: false).path
    let opened = try openLock(at: lockPath)
    let descriptor = opened.descriptor
    defer { close(descriptor) }

    if opened.created {
      guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0,
        fsync(descriptor) == 0,
        VendorAppOnboardingCursor.syncDirectory(directory)
      else { throw VendorAppOnboardingCursorError.stateUnavailable }
    }
    guard validateLock(descriptor, path: lockPath),
      flock(descriptor, LOCK_EX | LOCK_NB) == 0
    else { throw VendorAppOnboardingCursorError.stateUnavailable }
    defer { _ = flock(descriptor, LOCK_UN) }
    guard validateLock(descriptor, path: lockPath) else {
      throw VendorAppOnboardingCursorError.stateUnavailable
    }
    return try body()
  }

  private static func openLock(
    at path: String
  ) throws -> (descriptor: Int32, created: Bool) {
    let creationFlags = O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW
    let created = path.withCString {
      open($0, creationFlags, S_IRUSR | S_IWUSR)
    }
    if created >= 0 { return (created, true) }
    guard errno == EEXIST else {
      throw VendorAppOnboardingCursorError.stateUnavailable
    }
    let existing = path.withCString {
      open($0, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
    }
    guard existing >= 0 else {
      throw VendorAppOnboardingCursorError.stateUnavailable
    }
    return (existing, false)
  }

  private static func validateLock(_ descriptor: Int32, path: String) -> Bool {
    var descriptorState = stat()
    var pathState = stat()
    return fstat(descriptor, &descriptorState) == 0
      && path.withCString({ lstat($0, &pathState) }) == 0
      && descriptorState.st_dev == pathState.st_dev
      && descriptorState.st_ino == pathState.st_ino
      && descriptorState.st_mode & S_IFMT == S_IFREG
      && descriptorState.st_uid == getuid()
      && descriptorState.st_mode & permissionMask == S_IRUSR | S_IWUSR
      && descriptorState.st_nlink == 1
      && descriptorState.st_size == 0
      && VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor)
  }
}
