import Darwin
import Foundation
import PowerVPNCore

struct VendorAppNonLogoutHandoffDependencies: Sendable {
  let networkObserver: any NetworkCleanupObserving
  let launcher: any VendorAppHandoffLaunching
  let coldWaiter: any VendorAppHandoffColdWaiting
  let captureCursor: @Sendable () throws -> VendorAppOnboardingCursor
  let persistCursor: @Sendable (VendorAppOnboardingCursor) throws -> Void
  let clearCursor: @Sendable (VendorAppOnboardingCursor) -> Bool
  let observeBoundedPrefix: @Sendable (VendorAppOnboardingCursor) throws -> Bool
  let loadMaterial: @Sendable (VendorAppOnboardingCursor) throws -> VendorAppSessionSnapshotMaterial
  let publishProof:
    @Sendable (
      VendorAppOnboardingCursor, VendorAppNonLogoutHandoffProof
    ) throws -> Void
  let now: @Sendable () throws -> VendorAppCursorTimestamp
  let monotonicNowNanoseconds: @Sendable () -> UInt64
}

extension VendorAppNonLogoutHandoffDependencies {
  static let installed = Self(
    networkObserver: InstalledNetworkCleanupObserver(),
    launcher: InstalledVendorAppHandoffLauncher(),
    coldWaiter: InstalledVendorAppHandoffColdWaiter(),
    captureCursor: VendorAppOnboardingCursor.captureInstalledSource,
    persistCursor: { try $0.persistDefault() },
    clearCursor: { cursor in
      do {
        try cursor.consumeDefault()
        return true
      } catch {
        return false
      }
    },
    observeBoundedPrefix: { cursor in
      try VendorAppSessionSnapshotSource(cursor: cursor).validateBoundedPrefix()
    },
    loadMaterial: { cursor in
      try VendorAppSessionSnapshotSource(cursor: cursor).load().makeMaterial()
    },
    publishProof: { cursor, proof in
      _ = try cursor.publishHandoffProof(proof)
    },
    now: {
      var value = timespec()
      guard clock_gettime(CLOCK_REALTIME, &value) == 0 else {
        throw VendorAppOnboardingCursorError.stateUnavailable
      }
      return try VendorAppCursorTimestamp(value)
    },
    monotonicNowNanoseconds: { DispatchTime.now().uptimeNanoseconds }
  )
}

func finishAfterTermination(
  dependencies: VendorAppNonLogoutHandoffDependencies,
  application: any VendorAppHandoffApplication,
  cursor: VendorAppOnboardingCursor,
  window: NetworkCleanupCaptureWindow,
  before: NetworkCleanupSnapshot,
  approval: VendorAppNonLogoutHandoffApproval
) async -> VendorAppNonLogoutHandoffReport {
  let started = dependencies.monotonicNowNanoseconds()
  let totalNanoseconds: UInt64 = 60_000_000_000
  guard started <= UInt64.max - totalNanoseconds else {
    let cleared = dependencies.clearCursor(cursor)
    return postForceFailure(
      .cleanupUnproven,
      cleared: cleared,
      application: application,
      approval: approval
    )
  }
  let deadline = started + totalNanoseconds
  guard
    let coldTimeout = remainingMilliseconds(
      dependencies: dependencies,
      deadline: deadline,
      cap: 20_000
    ),
    let generation = await dependencies.coldWaiter.wait(
      application: application,
      timeoutMilliseconds: coldTimeout
    )
  else {
    let cleared = dependencies.clearCursor(cursor)
    return postForceFailure(
      .cleanupUnproven,
      cleared: cleared,
      application: application,
      approval: approval
    )
  }
  let observedCleanup = await waitForRestoredCleanup(
    dependencies: dependencies,
    deadline: deadline,
    window: window,
    before: before,
    generation: generation
  )
  guard let cleanup = observedCleanup, cleanup.allDimensionsRestored else {
    let cleared = dependencies.clearCursor(cursor)
    return report(
      .cleanupUnproven,
      baselineStable: true,
      cursorPersisted: !cleared,
      officialAppLaunched: true,
      secondApproval: approval,
      forceTerminationAccepted: true,
      exactReceiverTerminated: true,
      sourceSnapshotComplete: true,
      sourceObservation: .ready,
      officialAppStillRunning: false,
      cleanup: observedCleanup
    )
  }
  let finalMaterial = await waitForFinalMaterial(
    dependencies: dependencies,
    deadline: deadline,
    cursor: cursor
  )
  let material: VendorAppSessionSnapshotMaterial
  switch finalMaterial {
  case .ready(let readyMaterial):
    material = readyMaterial
  case .rejected(let sourceObservation):
    let cleared = dependencies.clearCursor(cursor)
    return report(
      .sourceNotReady,
      baselineStable: true,
      cursorPersisted: !cleared,
      officialAppLaunched: true,
      secondApproval: approval,
      forceTerminationAccepted: true,
      exactReceiverTerminated: true,
      sourceObservation: sourceObservation,
      officialAppStillRunning: false,
      cleanup: cleanup
    )
  }
  defer { material.erase() }
  guard material.validation.complete,
    material.sourceIsCurrent,
    let seal = material.sourceSeal,
    let finalRuns = generation.runs,
    let createdAt = try? dependencies.now()
  else {
    let cleared = dependencies.clearCursor(cursor)
    return report(
      .sourceNotReady,
      baselineStable: true,
      cursorPersisted: !cleared,
      officialAppLaunched: true,
      secondApproval: approval,
      forceTerminationAccepted: true,
      exactReceiverTerminated: true,
      sourceObservation: .missingSourceSeal,
      officialAppStillRunning: false,
      cleanup: cleanup
    )
  }
  let proof = VendorAppNonLogoutHandoffProof(
    cleanup: cleanup,
    finalSourceSeal: seal,
    finalHelperRuns: finalRuns,
    createdAt: createdAt
  )
  do {
    try dependencies.publishProof(cursor, proof)
    return report(
      .ready,
      baselineStable: true,
      cursorPersisted: true,
      officialAppLaunched: true,
      secondApproval: approval,
      forceTerminationAccepted: true,
      exactReceiverTerminated: true,
      sourceSnapshotComplete: true,
      sourceObservation: .ready,
      proofPersisted: true,
      officialAppStillRunning: false,
      cleanup: cleanup
    )
  } catch {
    let cleared = dependencies.clearCursor(cursor)
    return report(
      .proofRejected,
      baselineStable: true,
      cursorPersisted: !cleared,
      officialAppLaunched: true,
      secondApproval: approval,
      forceTerminationAccepted: true,
      exactReceiverTerminated: true,
      sourceSnapshotComplete: true,
      sourceObservation: .ready,
      officialAppStillRunning: false,
      cleanup: cleanup
    )
  }
}
