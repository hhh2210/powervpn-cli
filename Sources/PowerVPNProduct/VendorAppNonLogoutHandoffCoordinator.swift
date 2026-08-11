import Darwin
import Foundation
import PowerVPNCore

package struct VendorAppNonLogoutHandoffCoordinator: Sendable {
  private let dependencies: VendorAppNonLogoutHandoffDependencies

  package init() {
    dependencies = .installed
  }

  init(dependencies: VendorAppNonLogoutHandoffDependencies) {
    self.dependencies = dependencies
  }

  package func run(
    secondApproval: @escaping @Sendable () async -> VendorAppNonLogoutHandoffApproval
  ) async -> VendorAppNonLogoutHandoffReport {
    let window = NetworkCleanupCaptureWindow()
    let first = await dependencies.networkObserver.capture(
      window: window, selectedRoutes: nil, timeoutMilliseconds: 24_000)
    let before = await dependencies.networkObserver.capture(
      window: window, selectedRoutes: nil, timeoutMilliseconds: 24_000)
    guard NetworkCleanupAssessment.baselineStable(first, before) else {
      return report(.preflightRejected)
    }

    let cursor: VendorAppOnboardingCursor
    do {
      cursor = try dependencies.captureCursor()
      try dependencies.persistCursor(cursor)
    } catch {
      return report(.cursorRejected, baselineStable: true)
    }
    guard !Task.isCancelled else {
      return cancelled(cursor: cursor, baselineStable: true)
    }
    let application: any VendorAppHandoffApplication
    switch await dependencies.launcher.launch() {
    case .notLaunched:
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .launchRejected,
        baselineStable: true,
        cursorPersisted: !cleared
      )
    case .launchedButUnusable(let stillRunning):
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .launchRejected,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        officialAppStillRunning: stillRunning()
      )
    case .ready(let launched):
      application = launched
    }

    let approval = await secondApproval()
    guard !Task.isCancelled else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .cancelled,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        officialAppStillRunning: !application.isTerminated
      )
    }
    guard approval == .accepted else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        approval == .denied ? .approvalDenied : .approvalUnavailable,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        officialAppStillRunning: !application.isTerminated
      )
    }
    guard !Task.isCancelled else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .cancelled,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        officialAppStillRunning: !application.isTerminated
      )
    }

    let sourceObservation = await waitForFreshSnapshot(cursor)
    guard !Task.isCancelled else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .cancelled,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        sourceSnapshotComplete: sourceObservation == .ready,
        sourceObservation: sourceObservation,
        officialAppStillRunning: !application.isTerminated
      )
    }
    guard sourceObservation == .ready else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .sourceNotReady,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        sourceObservation: sourceObservation,
        officialAppStillRunning: !application.isTerminated
      )
    }
    guard !Task.isCancelled else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .cancelled,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        sourceSnapshotComplete: true,
        sourceObservation: .ready,
        officialAppStillRunning: !application.isTerminated
      )
    }
    guard application.identityIsCurrent, application.forceTerminate() else {
      let cleared = dependencies.clearCursor(cursor)
      return report(
        .terminationRejected,
        baselineStable: true,
        cursorPersisted: !cleared,
        officialAppLaunched: true,
        secondApproval: approval,
        sourceSnapshotComplete: true,
        sourceObservation: .ready,
        officialAppStillRunning: !application.isTerminated
      )
    }

    return await Task.detached {
      await finishAfterTermination(
        dependencies: dependencies,
        application: application,
        cursor: cursor,
        window: window,
        before: before,
        approval: approval
      )
    }.value
  }

  private func waitForFreshSnapshot(
    _ cursor: VendorAppOnboardingCursor
  ) async -> VendorAppNonLogoutHandoffSourceObservation {
    let started = dependencies.monotonicNowNanoseconds()
    let duration: UInt64 = 5_000_000_000
    guard started <= UInt64.max - duration else { return .sourceUnavailable }
    let deadline = started + duration
    var lastObservation = VendorAppNonLogoutHandoffSourceObservation.sourceUnavailable

    while !Task.isCancelled, dependencies.monotonicNowNanoseconds() < deadline {
      do {
        let complete = try dependencies.observeBoundedPrefix(cursor)
        if !complete {
          lastObservation = .snapshotIncomplete
        } else {
          return .ready
        }
      } catch let error as VendorAppSessionSnapshotError {
        lastObservation = VendorAppNonLogoutHandoffSourceObservation(error)
      } catch {
        lastObservation = .sourceUnavailable
      }
      guard !Task.isCancelled else { break }
      try? await Task.sleep(for: .milliseconds(200))
    }
    return lastObservation
  }

  private func cancelled(
    cursor: VendorAppOnboardingCursor,
    baselineStable: Bool
  ) -> VendorAppNonLogoutHandoffReport {
    let cleared = dependencies.clearCursor(cursor)
    return report(
      .cancelled,
      baselineStable: baselineStable,
      cursorPersisted: !cleared
    )
  }
}
