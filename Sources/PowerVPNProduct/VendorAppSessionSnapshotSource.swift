import Darwin
import Foundation

enum VendorAppSessionSnapshotError: Error, Equatable, Sendable {
  case unavailable
  case unsafeSource
  case stale
  case malformed
  case resourceUnavailable
  case incomplete
}

/// Reads only bytes appended after a value-free, pre-onboarding cursor.
struct VendorAppSessionSnapshotSource: Sendable {
  static let installedPath = VendorAppOnboardingCursor.installedSourcePath
  static let maximumAppendBytes = 65_536

  let cursor: VendorAppOnboardingCursor

  init(cursor: VendorAppOnboardingCursor) throws {
    try cursor.validate()
    self.cursor = cursor
  }

  func load() throws -> VendorAppSessionParsedInput {
    try cursor.validate()
    let descriptor = Self.installedPath.withCString {
      open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else { throw VendorAppSessionSnapshotError.unavailable }
    defer { close(descriptor) }

    var before = stat()
    guard fstat(descriptor, &before) == 0 else {
      throw VendorAppSessionSnapshotError.unavailable
    }
    let appendCount = try validatedAppendCount(before, descriptor: descriptor)
    let buffer = try VendorAppSessionAppendBuffer(count: appendCount)
    do {
      try readAppend(buffer, descriptor: descriptor)
      try requireStableSource(descriptor: descriptor, expected: before)
      let record = try buffer.withUnsafeBytes(
        VendorAppSessionRecordFraming.singleStartRecord)
      return VendorAppSessionParsedInput(
        buffer: buffer,
        dictionaryRange: record.dictionaryRange,
        root: record.root,
        sourceSeal: VendorAppSessionSourceSeal(before)
      )
    } catch {
      buffer.erase()
      throw error
    }
  }

  private func validatedAppendCount(_ metadata: stat, descriptor: Int32) throws -> Int {
    guard metadata.st_mode & S_IFMT == S_IFREG,
      metadata.st_uid == 0,
      metadata.st_mode & (S_IWGRP | S_IWOTH) == 0,
      metadata.st_nlink == 1,
      VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor),
      UInt64(metadata.st_dev) == cursor.device,
      UInt64(metadata.st_ino) == cursor.inode,
      UInt32(metadata.st_uid) == cursor.ownerUID,
      UInt32(metadata.st_mode) == cursor.mode,
      metadata.st_size >= 0,
      UInt64(metadata.st_size) > cursor.size,
      !Self.earlier(metadata.st_mtimespec, than: cursor.modificationTime.timespecValue),
      !Self.earlier(metadata.st_ctimespec, than: cursor.changeTime.timespecValue)
    else { throw VendorAppSessionSnapshotError.unsafeSource }
    let delta = UInt64(metadata.st_size) - cursor.size
    guard (1...UInt64(Self.maximumAppendBytes)).contains(delta) else {
      throw VendorAppSessionSnapshotError.unavailable
    }
    return Int(delta)
  }

  private func readAppend(
    _ buffer: VendorAppSessionAppendBuffer,
    descriptor: Int32
  ) throws {
    guard cursor.size <= UInt64(Int64.max) else {
      throw VendorAppSessionSnapshotError.unsafeSource
    }
    try buffer.withUnsafeMutableBytes { bytes in
      var total = 0
      while total < bytes.count {
        let result = pread(
          descriptor,
          bytes.baseAddress! + total,
          bytes.count - total,
          off_t(cursor.size) + off_t(total)
        )
        if result < 0 && errno == EINTR { continue }
        guard result > 0 else { throw VendorAppSessionSnapshotError.unavailable }
        total += result
      }
    }
  }

  private func requireStableSource(descriptor: Int32, expected: stat) throws {
    var after = stat()
    guard fstat(descriptor, &after) == 0,
      Self.exactMetadata(expected, after)
    else { throw VendorAppSessionSnapshotError.unavailable }
    var pathState = stat()
    guard Self.installedPath.withCString({ lstat($0, &pathState) }) == 0,
      Self.exactMetadata(expected, pathState)
    else { throw VendorAppSessionSnapshotError.unavailable }
  }

  private static func earlier(_ lhs: timespec, than rhs: timespec) -> Bool {
    lhs.tv_sec < rhs.tv_sec || (lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec < rhs.tv_nsec)
  }

  private static func exactMetadata(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_size == rhs.st_size
      && lhs.st_uid == rhs.st_uid && lhs.st_mode == rhs.st_mode
      && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
      && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
      && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
      && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
  }
}
