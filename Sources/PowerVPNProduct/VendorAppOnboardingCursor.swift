import Darwin
import Foundation
import PowerVPNCore

package struct VendorAppCursorTimestamp: Codable, Equatable, Sendable {
  package let seconds: Int64
  package let nanoseconds: Int32

  package init(seconds: Int64, nanoseconds: Int32) throws {
    guard (0..<1_000_000_000).contains(nanoseconds) else {
      throw VendorAppOnboardingCursorError.invalidCursor
    }
    self.seconds = seconds
    self.nanoseconds = nanoseconds
  }

  init(_ value: timespec) throws {
    try self.init(seconds: Int64(value.tv_sec), nanoseconds: Int32(value.tv_nsec))
  }

  var timespecValue: timespec {
    timespec(tv_sec: time_t(seconds), tv_nsec: Int(nanoseconds))
  }
}

package enum VendorAppOnboardingCursorError: Error, Equatable, Sendable {
  case sourceUnavailable
  case unsafeSource
  case unstableSource
  case unsafeStateDirectory
  case stateUnavailable
  case invalidCursor
}

/// Value-free boundary captured immediately before one official-app onboarding.
package struct VendorAppOnboardingCursor: Codable, Equatable, Sendable {
  package static let schemaVersion = 2
  package static let installedSourcePath = "/var/log/vsgvpn.log"
  package static let stateFileName = "vendor-onboarding-cursor.json"
  private static let permissionMask = mode_t(0o7777)

  package let schema: Int
  package let device: UInt64
  package let inode: UInt64
  package let size: UInt64
  package let ownerUID: UInt32
  package let mode: UInt32
  package let modificationTime: VendorAppCursorTimestamp
  package let changeTime: VendorAppCursorTimestamp
  package let capturedAt: VendorAppCursorTimestamp
  package let handoffProof: VendorAppNonLogoutHandoffProof?

  package init(
    schema: Int,
    device: UInt64,
    inode: UInt64,
    size: UInt64,
    ownerUID: UInt32,
    mode: UInt32,
    modificationTime: VendorAppCursorTimestamp,
    changeTime: VendorAppCursorTimestamp,
    capturedAt: VendorAppCursorTimestamp,
    handoffProof: VendorAppNonLogoutHandoffProof? = nil
  ) {
    self.schema = schema
    self.device = device
    self.inode = inode
    self.size = size
    self.ownerUID = ownerUID
    self.mode = mode
    self.modificationTime = modificationTime
    self.changeTime = changeTime
    self.capturedAt = capturedAt
    self.handoffProof = handoffProof
  }

  package static var defaultPath: String {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Application Support/powervpn-cli", isDirectory: true)
      .appendingPathComponent(stateFileName, isDirectory: false)
      .path
  }

  package static func captureInstalledSource() throws -> Self {
    guard !SystemInspector().installation().appRunning,
      LaunchdVendorHelperGenerationObserver().observe().exactInactive
    else { throw VendorAppOnboardingCursorError.unstableSource }
    let descriptor = installedSourcePath.withCString {
      open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else { throw VendorAppOnboardingCursorError.sourceUnavailable }
    defer { close(descriptor) }

    var observed = stat()
    guard fstat(descriptor, &observed) == 0 else {
      throw VendorAppOnboardingCursorError.sourceUnavailable
    }
    try validateInstalledSource(observed)
    guard VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor),
      VendorAppInstalledLogSecurity.endsAtLineBoundary(
        descriptor, size: observed.st_size)
    else { throw VendorAppOnboardingCursorError.unsafeSource }

    var pathState = stat()
    guard installedSourcePath.withCString({ lstat($0, &pathState) }) == 0,
      exactMetadata(observed, pathState)
    else { throw VendorAppOnboardingCursorError.unstableSource }

    var clock = timespec()
    guard clock_gettime(CLOCK_REALTIME, &clock) == 0 else {
      throw VendorAppOnboardingCursorError.stateUnavailable
    }
    return try Self(
      schema: schemaVersion,
      device: UInt64(observed.st_dev),
      inode: UInt64(observed.st_ino),
      size: UInt64(observed.st_size),
      ownerUID: UInt32(observed.st_uid),
      mode: UInt32(observed.st_mode),
      modificationTime: VendorAppCursorTimestamp(observed.st_mtimespec),
      changeTime: VendorAppCursorTimestamp(observed.st_ctimespec),
      capturedAt: VendorAppCursorTimestamp(clock),
      handoffProof: nil
    )
  }

  package static func captureAndPersistInstalledSource() throws -> Self {
    let cursor = try captureInstalledSource()
    try cursor.persistDefault()
    return cursor
  }

  package static func loadDefault() throws -> Self {
    try load(at: defaultPath)
  }

  static func load(at path: String) throws -> Self {
    try ensureStateDirectory(URL(fileURLWithPath: path).deletingLastPathComponent().path)
    let descriptor = path.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) }
    guard descriptor >= 0 else { throw VendorAppOnboardingCursorError.stateUnavailable }
    defer { close(descriptor) }

    var metadata = stat()
    let currentUID = getuid()
    guard fstat(descriptor, &metadata) == 0,
      metadata.st_mode & S_IFMT == S_IFREG,
      metadata.st_uid == currentUID,
      metadata.st_mode & permissionMask == S_IRUSR | S_IWUSR,
      metadata.st_nlink == 1,
      VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor),
      (1...4_096).contains(metadata.st_size)
    else { throw VendorAppOnboardingCursorError.invalidCursor }

    var bytes = Data(count: Int(metadata.st_size))
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
    guard readCount == count else { throw VendorAppOnboardingCursorError.stateUnavailable }
    var after = stat()
    var pathState = stat()
    guard fstat(descriptor, &after) == 0,
      exactMetadata(metadata, after),
      path.withCString({ lstat($0, &pathState) }) == 0,
      exactMetadata(metadata, pathState)
    else { throw VendorAppOnboardingCursorError.stateUnavailable }
    let cursor: Self
    do {
      cursor = try JSONDecoder().decode(Self.self, from: bytes)
    } catch {
      throw VendorAppOnboardingCursorError.invalidCursor
    }
    try cursor.validate()
    return cursor
  }

  package func validate() throws {
    guard schema == Self.schemaVersion,
      ownerUID == 0,
      mode_t(mode) & S_IFMT == S_IFREG,
      mode_t(mode) & (S_IWGRP | S_IWOTH) == 0,
      size <= UInt64(Int64.max),
      (0..<1_000_000_000).contains(modificationTime.nanoseconds),
      (0..<1_000_000_000).contains(changeTime.nanoseconds),
      (0..<1_000_000_000).contains(capturedAt.nanoseconds),
      handoffProof.map({ $0.isBound(to: self) }) ?? true
    else { throw VendorAppOnboardingCursorError.invalidCursor }
  }

  package func proving(_ proof: VendorAppNonLogoutHandoffProof) throws -> Self {
    guard handoffProof == nil, proof.isBound(to: self) else {
      throw VendorAppOnboardingCursorError.invalidCursor
    }
    return Self(
      schema: schema,
      device: device,
      inode: inode,
      size: size,
      ownerUID: ownerUID,
      mode: mode,
      modificationTime: modificationTime,
      changeTime: changeTime,
      capturedAt: capturedAt,
      handoffProof: proof
    )
  }

  private static func validateInstalledSource(_ metadata: stat) throws {
    guard metadata.st_mode & S_IFMT == S_IFREG,
      metadata.st_uid == 0,
      metadata.st_mode & (S_IWGRP | S_IWOTH) == 0,
      metadata.st_nlink == 1,
      metadata.st_size >= 0
    else { throw VendorAppOnboardingCursorError.unsafeSource }
  }

  static func exactMetadata(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_size == rhs.st_size
      && lhs.st_uid == rhs.st_uid && lhs.st_mode == rhs.st_mode
      && lhs.st_nlink == rhs.st_nlink
      && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
      && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
      && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
      && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
  }

  static func ensureStateDirectory(_ path: String) throws {
    let mode = S_IRWXU
    if path.withCString({ mkdir($0, mode) }) != 0 && errno != EEXIST {
      throw VendorAppOnboardingCursorError.stateUnavailable
    }
    var metadata = stat()
    guard path.withCString({ lstat($0, &metadata) }) == 0,
      metadata.st_mode & S_IFMT == S_IFDIR,
      metadata.st_uid == getuid(),
      metadata.st_mode & permissionMask == mode
    else { throw VendorAppOnboardingCursorError.unsafeStateDirectory }
  }

  static func syncDirectory(_ path: String) -> Bool {
    let descriptor = path.withCString {
      open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else { return false }
    defer { close(descriptor) }
    return fsync(descriptor) == 0
  }

}
