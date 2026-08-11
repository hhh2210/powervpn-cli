import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNProduct

@Suite struct VendorAppNonLogoutHandoffCoordinatorTests {
  @Test func exactReceiverTerminationPublishesOneValueFreeProof() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let after = handoffNetworkSnapshot(12)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before, after],
        finalGeneration: handoffInactiveGeneration(12),
        trace: trace
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .ready)
    #expect(result.readyForConnectOnce)
    #expect(result.baselineStable)
    #expect(result.forceTerminationAccepted)
    #expect(result.exactReceiverTerminated)
    #expect(result.proofPersisted)
    #expect(result.sourceObservation == .ready)
    #expect(!result.officialAppStillRunning)
    #expect(application.forceCount == 1)
    #expect(trace.count("observe") == 1)
    #expect(trace.count("load") == 1)
    #expect(trace.count("publish") == 1)
    #expect(trace.count("clear") == 0)

    let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
    #expect(encoded.contains("\"schemaVersion\":2"))
    #expect(encoded.contains("\"sourceObservation\":\"ready\""))
    for forbidden in ["synthetic-psk", "synthetic-session", "gateway", "inode"] {
      #expect(!encoded.contains(forbidden))
    }
  }

  @Test func deniedSecondApprovalNeverTerminatesAndClearsCursor() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace
      )
    )

    let result = await coordinator.run(secondApproval: { .denied })

    #expect(result.outcome == .approvalDenied)
    #expect(result.officialAppStillRunning)
    #expect(application.forceCount == 0)
    #expect(trace.count("load") == 0)
    #expect(trace.count("publish") == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func forceRejectionNeverPublishesProof() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication(forceAccepted: false)
    let before = handoffNetworkSnapshot(10)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .terminationRejected)
    #expect(result.sourceSnapshotComplete)
    #expect(result.sourceObservation == .ready)
    #expect(result.officialAppStillRunning)
    #expect(application.forceCount == 1)
    #expect(trace.count("observe") == 1)
    #expect(trace.count("load") == 0)
    #expect(trace.count("publish") == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func incompleteCleanupCannotPublishProof() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let unavailable = NetworkCleanupSnapshot.unavailable(.commandFailed)
    let clock = HandoffScriptedClock([
      0, 0, 0, 0, 40_000_000_000, 60_000_000_000,
    ])
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before, unavailable],
        finalGeneration: handoffInactiveGeneration(12),
        trace: trace,
        monotonicNowNanoseconds: clock.now
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .cleanupUnproven)
    #expect(result.forceTerminationAccepted)
    #expect(result.exactReceiverTerminated)
    #expect(result.sourceObservation == .ready)
    #expect(result.cleanup?.allDimensionsRestored == false)
    #expect(trace.count("publish") == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func cancellationDuringSnapshotValidationNeverForcesReceiver() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace,
        prefixObservation: {
          withUnsafeCurrentTask { $0?.cancel() }
          return true
        }
      )
    )

    let task = Task { await coordinator.run(secondApproval: { .accepted }) }
    let result = await task.value

    #expect(result.outcome == .cancelled)
    #expect(result.sourceSnapshotComplete)
    #expect(application.forceCount == 0)
    #expect(trace.count("publish") == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func launchedButUnusableIsReportedAsRunningAndNeverForced() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace,
        launcher: HandoffUnusableLauncher(stillRunning: true)
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .launchRejected)
    #expect(result.officialAppLaunched)
    #expect(result.officialAppStillRunning)
    #expect(application.forceCount == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func boundedCleanupPollAcceptsLaterRestoredSample() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let unavailable = NetworkCleanupSnapshot.unavailable(.changedDuringCapture)
    let after = handoffNetworkSnapshot(12)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before, unavailable, after],
        finalGeneration: handoffInactiveGeneration(12),
        trace: trace
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .ready)
    #expect(result.cleanup?.allDimensionsRestored == true)
    #expect(application.forceCount == 1)
    #expect(trace.count("publish") == 1)
  }

  @Test func cancellationAcceptedDuringForceStillCompletesDetachedCleanup() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication(cancelOnForce: true)
    let before = handoffNetworkSnapshot(10)
    let after = handoffNetworkSnapshot(12)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before, after],
        finalGeneration: handoffInactiveGeneration(12),
        trace: trace
      )
    )

    let task = Task { await coordinator.run(secondApproval: { .accepted }) }
    let result = await task.value

    #expect(result.outcome == .ready)
    #expect(result.cleanup?.allDimensionsRestored == true)
    #expect(application.forceCount == 1)
    #expect(trace.count("publish") == 1)
  }
}
