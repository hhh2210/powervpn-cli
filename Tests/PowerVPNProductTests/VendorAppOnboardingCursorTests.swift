import Darwin
import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppInstalledLogSecurityTests {
  @Test func extendedACLIsRejected() throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("powervpn-acl-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("source.log")
    try #require(FileManager.default.createFile(atPath: file.path, contents: Data()))
    let descriptor = file.path.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) }
    try #require(descriptor >= 0)
    defer { close(descriptor) }
    #expect(VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor))

    let chmod = Process()
    chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
    chmod.arguments = ["+a", "everyone deny write", file.path]
    try chmod.run()
    chmod.waitUntilExit()
    try #require(chmod.terminationStatus == 0)
    #expect(!VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor))
  }
}

@Suite struct VendorAppOnboardingCursorTests {
  @Test func persistLoadAndConsumeKeepStableSidecarLock() throws {
    let paths = try temporaryPaths()
    defer { try? FileManager.default.removeItem(atPath: paths.directory) }
    let cursor = try syntheticCursor(inode: 41)

    try cursor.persist(at: paths.cursor)
    #expect(try VendorAppOnboardingCursor.load(at: paths.cursor) == cursor)
    try cursor.consume(at: paths.cursor)

    #expect(!FileManager.default.fileExists(atPath: paths.cursor))
    #expect(FileManager.default.fileExists(atPath: paths.lock))
  }

  @Test func writerCannotPublishWhileConsumerOwnsStableLockAndNextCursorSurvives() async throws {
    let paths = try temporaryPaths()
    defer { try? FileManager.default.removeItem(atPath: paths.directory) }
    let first = try syntheticCursor(inode: 51)
    let next = try syntheticCursor(inode: 52)
    try first.persist(at: paths.cursor)

    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let consumer = Task {
      await withCheckedContinuation { continuation in
        DispatchQueue.global().async {
          do {
            try first.consume(at: paths.cursor) {
              entered.signal()
              _ = release.wait(timeout: .now() + .seconds(5))
            }
            continuation.resume(returning: true)
          } catch {
            continuation.resume(returning: false)
          }
        }
      }
    }
    let reachedCriticalSection = await wait(
      for: entered,
      timeout: .now() + .seconds(2)
    )
    guard reachedCriticalSection else {
      release.signal()
      _ = await consumer.value
      Issue.record("consumer did not reach the locked pre-unlink boundary")
      return
    }

    do {
      try next.persist(at: paths.cursor)
      Issue.record("writer published a replacement while consume held the sidecar lock")
    } catch let error as VendorAppOnboardingCursorError {
      #expect(error == .stateUnavailable)
    } catch {
      Issue.record("unexpected writer error: \(error)")
    }
    release.signal()
    #expect(await consumer.value)

    try next.persist(at: paths.cursor)
    #expect(try VendorAppOnboardingCursor.load(at: paths.cursor) == next)
  }

  @Test func postRenameFailureRollsBackInsteadOfLeavingAnArmedCursor() throws {
    enum InjectedFailure: Error { case afterRename }
    let paths = try temporaryPaths()
    defer { try? FileManager.default.removeItem(atPath: paths.directory) }
    let previous = try syntheticCursor(inode: 71)
    let replacement = try syntheticCursor(inode: 72)
    try previous.persist(at: paths.cursor)

    #expect(throws: InjectedFailure.self) {
      try replacement.persist(at: paths.cursor) {
        throw InjectedFailure.afterRename
      }
    }
    #expect(!FileManager.default.fileExists(atPath: paths.cursor))
    #expect(throws: VendorAppOnboardingCursorError.self) {
      _ = try VendorAppOnboardingCursor.load(at: paths.cursor)
    }
    #expect(FileManager.default.fileExists(atPath: paths.lock))
  }

  @Test func proofPublicationCompareAndSwapsOnlyTheExactArmedCursor() throws {
    let paths = try temporaryPaths()
    defer { try? FileManager.default.removeItem(atPath: paths.directory) }
    let armed = try syntheticCursor(inode: 81)
    try armed.persist(at: paths.cursor)

    let proven = try armed.publishHandoffProof(
      try syntheticProof(for: armed),
      at: paths.cursor
    )
    #expect(proven.handoffProof != nil)
    #expect(try VendorAppOnboardingCursor.load(at: paths.cursor) == proven)

    #expect(throws: VendorAppOnboardingCursorError.self) {
      _ = try armed.publishHandoffProof(
        try syntheticProof(for: armed),
        at: paths.cursor
      )
    }
    #expect(try VendorAppOnboardingCursor.load(at: paths.cursor) == proven)
  }

  @Test func proofPublicationRejectsAReplacedCursorWithoutRemovingIt() throws {
    let paths = try temporaryPaths()
    defer { try? FileManager.default.removeItem(atPath: paths.directory) }
    let armed = try syntheticCursor(inode: 91)
    let replacement = try syntheticCursor(inode: 92)
    try armed.persist(at: paths.cursor)
    try replacement.persist(at: paths.cursor)

    #expect(throws: VendorAppOnboardingCursorError.self) {
      _ = try armed.publishHandoffProof(
        try syntheticProof(for: armed),
        at: paths.cursor
      )
    }
    #expect(try VendorAppOnboardingCursor.load(at: paths.cursor) == replacement)
  }

  private func temporaryPaths() throws -> (directory: String, cursor: String, lock: String) {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("powervpn-cursor-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: NSNumber(value: 0o700)]
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: NSNumber(value: 0o700)],
      ofItemAtPath: directory.path
    )
    return (
      directory.path,
      directory.appendingPathComponent(VendorAppOnboardingCursor.stateFileName).path,
      directory.appendingPathComponent(VendorAppCursorStateLock.fileName).path
    )
  }

  private func syntheticCursor(inode: UInt64) throws -> VendorAppOnboardingCursor {
    let timestamp = try VendorAppCursorTimestamp(seconds: 1_723_000_000, nanoseconds: 123)
    return VendorAppOnboardingCursor(
      schema: VendorAppOnboardingCursor.schemaVersion,
      device: 7,
      inode: inode,
      size: 1_024,
      ownerUID: 0,
      mode: UInt32(S_IFREG | S_IRUSR | S_IWUSR),
      modificationTime: timestamp,
      changeTime: timestamp,
      capturedAt: timestamp
    )
  }

  private func syntheticProof(
    for cursor: VendorAppOnboardingCursor
  ) throws -> VendorAppNonLogoutHandoffProof {
    VendorAppNonLogoutHandoffProof(
      cleanup: VendorAppNonLogoutHandoffCleanupProof(
        complete: true,
        defaultRouteRestored: true,
        dnsRestored: true,
        interfacesRestored: true,
        utunRestored: true,
        persistentRoutesRestored: true,
        surgeStateRestored: true,
        vendorProcessesAbsent: true,
        helperInactive: true,
        structuralRouteTablesEqual: true
      ),
      finalSourceSeal: VendorAppSessionSourceSeal(
        device: cursor.device,
        inode: cursor.inode,
        size: Int64(cursor.size + 512),
        ownerUID: cursor.ownerUID,
        mode: cursor.mode,
        modificationSeconds: cursor.modificationTime.seconds + 1,
        modificationNanoseconds: 0,
        changeSeconds: cursor.changeTime.seconds + 1,
        changeNanoseconds: 0
      ),
      finalHelperRuns: 21,
      createdAt: try VendorAppCursorTimestamp(
        seconds: cursor.capturedAt.seconds + 1,
        nanoseconds: 0
      )
    )
  }

  private func wait(
    for semaphore: DispatchSemaphore,
    timeout: DispatchTime
  ) async -> Bool {
    await withCheckedContinuation { continuation in
      DispatchQueue.global().async {
        continuation.resume(returning: semaphore.wait(timeout: timeout) == .success)
      }
    }
  }
}
