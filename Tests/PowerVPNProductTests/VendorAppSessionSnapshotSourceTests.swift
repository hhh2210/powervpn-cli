import Darwin
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppSessionSnapshotSourceTests {
  @Test func boundedPrefixAcceptsMonotonicAppendDuringRead() throws {
    let cursor = try sourceCursor()
    let prefix = sourceMetadata(size: 2_048, timestamp: 101)
    let descriptorAfter = sourceMetadata(size: 2_200, timestamp: 102)
    let pathAfter = sourceMetadata(size: 2_300, timestamp: 103)
    let descriptorFinal = sourceMetadata(size: 2_400, timestamp: 104)

    try VendorAppSessionSnapshotSource.validateBoundedPrefixMetadata(
      cursor: cursor,
      prefix: prefix,
      postRead: [descriptorAfter, pathAfter, descriptorFinal]
    )
  }

  @Test func boundedPrefixRejectsRotationShrinkAndSecurityChange() throws {
    let cursor = try sourceCursor()
    let prefix = sourceMetadata(size: 2_048, timestamp: 101)
    let rotated = sourceMetadata(size: 2_200, timestamp: 102, inode: 8)
    let shrunk = sourceMetadata(size: 2_047, timestamp: 102)
    let writable = sourceMetadata(
      size: 2_200,
      timestamp: 102,
      mode: S_IFREG | S_IRUSR | S_IWUSR | S_IWGRP
    )

    for changed in [rotated, shrunk, writable] {
      #expect(throws: VendorAppSessionSnapshotError.unsafeSource) {
        try VendorAppSessionSnapshotSource.validateBoundedPrefixMetadata(
          cursor: cursor,
          prefix: prefix,
          postRead: [changed]
        )
      }
    }
  }

  @Test func boundedPrefixRejectsAppendBeyondMaximumWindow() throws {
    let cursor = try sourceCursor()
    let prefix = sourceMetadata(size: 2_048, timestamp: 101)
    let oversized = sourceMetadata(
      size: Int64(cursor.size) + Int64(VendorAppSessionSnapshotSource.maximumAppendBytes) + 1,
      timestamp: 102
    )

    #expect(throws: VendorAppSessionSnapshotError.appendTooLarge) {
      try VendorAppSessionSnapshotSource.validateBoundedPrefixMetadata(
        cursor: cursor,
        prefix: prefix,
        postRead: [oversized]
      )
    }
  }

  @Test func capturedPrefixRejectsLatestLogoutAndMalformedRPC() throws {
    let start = vendorAppSyntheticRecord()
    let logout = vendorAppSyntheticRecord(
      root: "{\n  type = rpc;\n  rpc = logout;\n}"
    )
    let malformed = vendorAppSyntheticRecord(
      root: "{\n  type = rpc;\n  rpc = unexpected;\n}"
    )

    #expect(throws: VendorAppSessionSnapshotError.stale) {
      _ = try vendorAppLocatedRecord(start + logout)
    }
    #expect(throws: VendorAppSessionSnapshotError.malformed) {
      _ = try vendorAppLocatedRecord(start + malformed)
    }
  }

  @Test func capturedPrefixAllowsBenignRecordAfterStart() throws {
    let getVersion = vendorAppSyntheticRecord(
      root: "{\n  type = rpc;\n  rpc = get_version;\n}"
    )
    _ = try vendorAppLocatedRecord(vendorAppSyntheticRecord() + getVersion)
  }

  private func sourceCursor() throws -> VendorAppOnboardingCursor {
    let timestamp = try VendorAppCursorTimestamp(seconds: 100, nanoseconds: 0)
    return VendorAppOnboardingCursor(
      schema: VendorAppOnboardingCursor.schemaVersion,
      device: 7,
      inode: 9,
      size: 1_024,
      ownerUID: 0,
      mode: UInt32(S_IFREG | S_IRUSR | S_IWUSR),
      modificationTime: timestamp,
      changeTime: timestamp,
      capturedAt: timestamp
    )
  }

  private func sourceMetadata(
    size: Int64,
    timestamp: Int,
    inode: UInt64 = 9,
    mode: mode_t = S_IFREG | S_IRUSR | S_IWUSR
  ) -> stat {
    var value = stat()
    value.st_dev = dev_t(7)
    value.st_ino = ino_t(inode)
    value.st_mode = mode
    value.st_nlink = nlink_t(1)
    value.st_uid = uid_t(0)
    value.st_size = off_t(size)
    value.st_mtimespec = timespec(tv_sec: timestamp, tv_nsec: 0)
    value.st_ctimespec = timespec(tv_sec: timestamp, tv_nsec: 0)
    return value
  }
}
