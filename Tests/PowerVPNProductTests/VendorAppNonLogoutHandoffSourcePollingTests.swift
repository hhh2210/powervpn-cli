import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppNonLogoutHandoffSourcePollingTests {
  @Test func finalSealedPollAcceptsLaterStableRecord() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let after = handoffNetworkSnapshot(12)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before, after],
        finalGeneration: handoffInactiveGeneration(12),
        trace: trace,
        materialFactory: {
          if trace.count("load") == 1 {
            throw VendorAppSessionSnapshotError.unavailable
          }
          return try vendorAppMaterial(
            sourceSeal: handoffSourceSeal(),
            sourceCurrent: { true }
          )
        }
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .ready)
    #expect(result.sourceObservation == .ready)
    #expect(trace.count("observe") == 1)
    #expect(trace.count("load") == 2)
    #expect(trace.count("publish") == 1)
  }

  @Test func boundedPreForcePollAcceptsLaterCompletePrefix() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let after = handoffNetworkSnapshot(12)
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before, after],
        finalGeneration: handoffInactiveGeneration(12),
        trace: trace,
        prefixObservation: {
          if trace.count("observe") == 1 {
            throw VendorAppSessionSnapshotError.incomplete
          }
          return true
        }
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .ready)
    #expect(result.sourceObservation == .ready)
    #expect(trace.count("observe") == 2)
    #expect(trace.count("load") == 1)
    #expect(application.forceCount == 1)
  }

  @Test func preForcePollReportsLastValueFreeSourceFailure() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let clock = HandoffScriptedClock([0, 0, 5_000_000_000])
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace,
        prefixObservation: {
          throw VendorAppSessionSnapshotError.changedDuringRead
        },
        monotonicNowNanoseconds: clock.now
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .sourceNotReady)
    #expect(result.sourceObservation == .changedDuringRead)
    #expect(!result.sourceSnapshotComplete)
    #expect(application.forceCount == 0)
    #expect(trace.count("clear") == 1)
  }

  @Test func fixedRequiredFieldFailureReachesProductReport() async throws {
    let trace = HandoffTrace()
    let application = HandoffApplication()
    let before = handoffNetworkSnapshot(10)
    let clock = HandoffScriptedClock([0, 0, 5_000_000_000])
    let coordinator = VendorAppNonLogoutHandoffCoordinator(
      dependencies: try handoffDependencies(
        application: application,
        snapshots: [before, before],
        finalGeneration: nil,
        trace: trace,
        prefixObservation: {
          throw VendorAppSessionSnapshotError.requiredFieldMissing(.commonGateway)
        },
        monotonicNowNanoseconds: clock.now
      )
    )

    let result = await coordinator.run(secondApproval: { .accepted })

    #expect(result.outcome == .sourceNotReady)
    #expect(result.sourceObservation == .requiredFieldMissing)
    #expect(result.sourceRequiredField == .commonGateway)
    #expect(application.forceCount == 0)
  }
}
