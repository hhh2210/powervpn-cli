import Foundation
import PowerVPNCore

func waitForRestoredCleanup(
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

enum VendorAppFinalMaterialPollResult {
  case ready(VendorAppSessionSnapshotMaterial)
  case rejected(VendorAppNonLogoutHandoffSourceObservation)
}

func waitForFinalMaterial(
  dependencies: VendorAppNonLogoutHandoffDependencies,
  deadline: UInt64,
  cursor: VendorAppOnboardingCursor
) async -> VendorAppFinalMaterialPollResult {
  var lastObservation = VendorAppNonLogoutHandoffSourceObservation.sourceUnavailable
  while remainingMilliseconds(
    dependencies: dependencies,
    deadline: deadline,
    cap: 200
  ) != nil {
    do {
      let material = try dependencies.loadMaterial(cursor)
      if !material.validation.complete {
        lastObservation = .snapshotIncomplete
        material.erase()
      } else if !material.sourceIsCurrent {
        lastObservation = .changedDuringRead
        material.erase()
      } else if material.sourceSeal == nil {
        lastObservation = .missingSourceSeal
        material.erase()
      } else {
        return .ready(material)
      }
    } catch let error as VendorAppSessionSnapshotError {
      lastObservation = VendorAppNonLogoutHandoffSourceObservation(error)
    } catch {
      lastObservation = .sourceUnavailable
    }
    try? await Task.sleep(for: .milliseconds(200))
  }
  return .rejected(lastObservation)
}

func remainingMilliseconds(
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

func postForceFailure(
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
    sourceObservation: .ready,
    officialAppStillRunning: !application.isTerminated
  )
}
