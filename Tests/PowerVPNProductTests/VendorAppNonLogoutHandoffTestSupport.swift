import Darwin
import Foundation

@testable import PowerVPNCore
@testable import PowerVPNProduct

func handoffInactiveGeneration(_ runs: Int) -> VendorHelperGenerationSnapshot {
  VendorHelperGenerationSnapshot(
    launchdObserved: true,
    running: false,
    inactiveConfirmed: true,
    activeCount: 0,
    pid: nil,
    runs: runs
  )
}

func handoffNetworkSnapshot(_ runs: Int) -> NetworkCleanupSnapshot {
  m2ObservedNetworkBaseline(generation: handoffInactiveGeneration(runs)).snapshot!
}

func handoffCursor() throws -> VendorAppOnboardingCursor {
  let timestamp = try VendorAppCursorTimestamp(seconds: 1_723_000_000, nanoseconds: 123)
  return VendorAppOnboardingCursor(
    schema: VendorAppOnboardingCursor.schemaVersion,
    device: 7,
    inode: 101,
    size: 1_024,
    ownerUID: 0,
    mode: UInt32(S_IFREG | S_IRUSR | S_IWUSR),
    modificationTime: timestamp,
    changeTime: timestamp,
    capturedAt: timestamp
  )
}

func handoffSourceSeal() -> VendorAppSessionSourceSeal {
  VendorAppSessionSourceSeal(
    device: 7,
    inode: 101,
    size: 2_048,
    ownerUID: 0,
    mode: UInt32(S_IFREG | S_IRUSR | S_IWUSR),
    modificationSeconds: 1_723_000_001,
    modificationNanoseconds: 0,
    changeSeconds: 1_723_000_001,
    changeNanoseconds: 0
  )
}

actor HandoffNetworkObserver: NetworkCleanupObserving {
  private var snapshots: [NetworkCleanupSnapshot]

  init(_ snapshots: [NetworkCleanupSnapshot]) {
    self.snapshots = snapshots
  }

  func capture(
    window _: NetworkCleanupCaptureWindow,
    selectedRoutes _: VendorCharonSelectedRouteMatcher?,
    timeoutMilliseconds _: Int
  ) -> NetworkCleanupSnapshot {
    guard !snapshots.isEmpty else { return .unavailable(.commandFailed) }
    return snapshots.removeFirst()
  }
}

final class HandoffApplication: VendorAppHandoffApplication, @unchecked Sendable {
  private let lock = NSLock()
  private let forceAccepted: Bool
  private let cancelOnForce: Bool
  private var terminated = false
  private(set) var forceCount = 0

  init(forceAccepted: Bool = true, cancelOnForce: Bool = false) {
    self.forceAccepted = forceAccepted
    self.cancelOnForce = cancelOnForce
  }

  var identityIsCurrent: Bool { lock.withLock { !terminated } }
  var isTerminated: Bool { lock.withLock { terminated } }

  func forceTerminate() -> Bool {
    if cancelOnForce { withUnsafeCurrentTask { $0?.cancel() } }
    return lock.withLock {
      forceCount += 1
      if forceAccepted { terminated = true }
      return forceAccepted
    }
  }
}

struct HandoffLauncher: VendorAppHandoffLaunching {
  let application: (any VendorAppHandoffApplication)?
  func launch() async -> VendorAppHandoffLaunchResult {
    application.map(VendorAppHandoffLaunchResult.ready) ?? .notLaunched
  }
}

struct HandoffUnusableLauncher: VendorAppHandoffLaunching {
  let stillRunning: Bool
  func launch() async -> VendorAppHandoffLaunchResult {
    .launchedButUnusable(stillRunning: { stillRunning })
  }
}

struct HandoffColdWaiter: VendorAppHandoffColdWaiting {
  let generation: VendorHelperGenerationSnapshot?
  func wait(
    application _: any VendorAppHandoffApplication,
    timeoutMilliseconds _: Int
  ) async -> VendorHelperGenerationSnapshot? { generation }
}

final class HandoffTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [String] = []

  func record(_ value: String) { lock.withLock { values.append(value) } }
  func count(_ value: String) -> Int { lock.withLock { values.count { $0 == value } } }
}

final class HandoffScriptedClock: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [UInt64]
  private var last: UInt64

  init(_ values: [UInt64]) {
    precondition(!values.isEmpty)
    self.values = values
    last = values.last!
  }

  func now() -> UInt64 {
    lock.withLock {
      guard !values.isEmpty else { return last }
      last = values.removeFirst()
      return last
    }
  }
}

func handoffDependencies(
  application: HandoffApplication,
  snapshots: [NetworkCleanupSnapshot],
  finalGeneration: VendorHelperGenerationSnapshot?,
  trace: HandoffTrace,
  launcher: (any VendorAppHandoffLaunching)? = nil,
  clearResult: Bool = true,
  prefixObservation: @escaping @Sendable () throws -> Bool = { true },
  materialFactory: @escaping @Sendable () throws -> VendorAppSessionSnapshotMaterial = {
    try vendorAppMaterial(
      sourceSeal: handoffSourceSeal(),
      sourceCurrent: { true }
    )
  },
  monotonicNowNanoseconds: @escaping @Sendable () -> UInt64 = { 1_000_000_000 }
) throws -> VendorAppNonLogoutHandoffDependencies {
  let cursor = try handoffCursor()
  return VendorAppNonLogoutHandoffDependencies(
    networkObserver: HandoffNetworkObserver(snapshots),
    launcher: launcher ?? HandoffLauncher(application: application),
    coldWaiter: HandoffColdWaiter(generation: finalGeneration),
    captureCursor: { cursor },
    persistCursor: { _ in trace.record("persist") },
    clearCursor: { _ in
      trace.record("clear")
      return clearResult
    },
    observeBoundedPrefix: { _ in
      trace.record("observe")
      return try prefixObservation()
    },
    loadMaterial: { _ in
      trace.record("load")
      return try materialFactory()
    },
    publishProof: { armed, proof in
      _ = try armed.proving(proof)
      trace.record("publish")
    },
    now: {
      try VendorAppCursorTimestamp(seconds: 1_723_000_002, nanoseconds: 0)
    },
    monotonicNowNanoseconds: monotonicNowNanoseconds
  )
}
