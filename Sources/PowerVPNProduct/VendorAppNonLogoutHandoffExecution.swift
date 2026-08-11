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
      officialAppStillRunning: false,
      cleanup: observedCleanup
    )
  }
  guard
    let material = await waitForFinalMaterial(
      dependencies: dependencies,
      deadline: deadline,
      cursor: cursor
    )
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
      officialAppStillRunning: false,
      cleanup: cleanup
    )
  }
}

private func waitForRestoredCleanup(
  dependencies: VendorAppNonLogoutHandoffDependencies,
  deadline: UInt64,
  window: NetworkCleanupCaptureWindow,
  before: NetworkCleanupSnapshot,
  generation: VendorHelperGenerationSnapshot
) async -> VendorAppNonLogoutHandoffCleanupProof? {
  var lastObservation: VendorAppNonLogoutHandoffCleanupProof?
  while let timeout = remainingMilliseconds(
    dependencies: dependencies,
    deadline: deadline,
    cap: 12_000
  ) {
    let after = await dependencies.networkObserver.capture(
      window: window,
      selectedRoutes: nil,
      timeoutMilliseconds: timeout
    )
    let cleanup = VendorAppNonLogoutHandoffCleanupAssessment.assess(
      before: before,
      after: after,
      finalGeneration: generation
    )
    lastObservation = cleanup
    if cleanup.allDimensionsRestored { return cleanup }
    guard
      remainingMilliseconds(
        dependencies: dependencies,
        deadline: deadline,
        cap: 200
      ) != nil
    else { return lastObservation }
    try? await Task.sleep(for: .milliseconds(200))
  }
  return lastObservation
}

private func waitForFinalMaterial(
  dependencies: VendorAppNonLogoutHandoffDependencies,
  deadline: UInt64,
  cursor: VendorAppOnboardingCursor
) async -> VendorAppSessionSnapshotMaterial? {
  while remainingMilliseconds(
    dependencies: dependencies,
    deadline: deadline,
    cap: 200
  ) != nil {
    if let material = try? dependencies.loadMaterial(cursor) {
      if material.validation.complete, material.sourceIsCurrent, material.sourceSeal != nil {
        return material
      }
      material.erase()
    }
    try? await Task.sleep(for: .milliseconds(200))
  }
  return nil
}

private func remainingMilliseconds(
  dependencies: VendorAppNonLogoutHandoffDependencies,
  deadline: UInt64,
  cap: Int
) -> Int? {
  let current = dependencies.monotonicNowNanoseconds()
  guard current < deadline, cap > 0 else { return nil }
  let remaining = (deadline - current) / 1_000_000
  guard remaining > 0 else { return nil }
  return min(cap, Int(remaining))
}

private func postForceFailure(
  _ outcome: VendorAppNonLogoutHandoffOutcome,
  cleared: Bool,
  application: any VendorAppHandoffApplication,
  approval: VendorAppNonLogoutHandoffApproval
) -> VendorAppNonLogoutHandoffReport {
  report(
    outcome,
    baselineStable: true,
    cursorPersisted: !cleared,
    officialAppLaunched: true,
    secondApproval: approval,
    forceTerminationAccepted: true,
    exactReceiverTerminated: application.isTerminated,
    sourceSnapshotComplete: true,
    officialAppStillRunning: !application.isTerminated
  )
}
