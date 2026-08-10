import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2ProvisionalCleanupTests {
  @Test(arguments: [
    ProductM2ControlOutcome.cancelled,
    .timeout,
    .peerGenerationMismatch,
  ])
  func submittedStartFailureAttemptsOneProvisionalStop(
    _ startOutcome: ProductM2ControlOutcome
  ) async throws {
    let (report, trace) = try await run(plan: .submittedFailure(startOutcome))

    #expect(report.startOutcome == startOutcome)
    #expect(report.outcome == (startOutcome == .cancelled ? .cancelled : .startRejected))
    #expect(report.lastGoodState == .connecting)
    #expect(report.cleanupPath == .sameSessionProvisionalStop)
    #expect(report.stopOutcome == .transportAcknowledged)
    #expect(report.emergencyStopOutcome == .notAttempted)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
    #expect(trace.count("ssh") == 0)
  }

  @Test func preSubmissionFailureHasNoCapabilityAndSendsNoStop() async throws {
    let (report, trace) = try await run(plan: .preSubmissionFailure)

    #expect(!report.helperMutationRequested)
    #expect(report.cleanupPath == .notRequired)
    #expect(trace.count("stop") == 0)
    #expect(trace.count("emergency_stop") == 0)
  }

  @Test(arguments: [
    ProductM2ControlOutcome.connectionInvalid,
    .leaseClosed,
  ])
  func unsentProvisionalStopFallsBackToAuthenticatedEmergencyStop(
    _ stopOutcome: ProductM2ControlOutcome
  ) async throws {
    let (report, trace) = try await run(
      plan: .submittedFailure(
        .timeout,
        stopOutcome: stopOutcome,
        stopRequestSent: false
      )
    )

    #expect(report.stopOutcome == stopOutcome)
    #expect(report.cleanupPath == .authenticatedEmergencyStop)
    #expect(report.emergencyStopOutcome == .transportAcknowledged)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 1)
  }

  @Test func activeLeaseDoesNotAlsoUseProvisionalStop() async throws {
    let (report, trace) = try await run(plan: .acknowledged)

    #expect(report.cleanupPath == .sameLeaseStop)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 0)
  }

  @Test func cancelledParentStillClassifiesRunningHelperAndEmergencyStops() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: .submittedFailure(
        .cancelled,
        generation: m2RunningGeneration,
        stopOutcome: .connectionInvalid,
        stopRequestSent: false
      ),
      generationObservationHonorsCancellation: true
    )
    let coordinator = ProductM2ConnectOnceCoordinator(dependencies: dependencies)
    let operation = Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
        budget: m2TestBudget()
      )
    }
    let report = await operation.value

    #expect(report.outcome == .cancelled)
    #expect(report.finalState == .disconnected)
    #expect(report.cleanupVerified)
    #expect(report.cleanupPath == .authenticatedEmergencyStop)
    #expect(report.stopOutcome == .connectionInvalid)
    #expect(report.emergencyStopOutcome == .transportAcknowledged)
    #expect(trace.count("cancelled_observe_generation") == 0)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("emergency_stop") == 1)
  }

  @Test func cleanupPathJSONMappingIsClosedAndDistinguishesAuthority() throws {
    let rawValues = Set(ProductM2CleanupPath.allCases.map(\.rawValue))
    #expect(
      rawValues == [
        "not_required",
        "same_lease_stop",
        "same_session_provisional_stop",
        "natural_helper_exit",
        "authenticated_emergency_stop",
        "cleanup_unproven",
      ])
    let encoded = String(
      decoding: try JSONEncoder().encode(ProductM2CleanupPath.sameSessionProvisionalStop),
      as: UTF8.self
    )
    #expect(encoded == "\"same_session_provisional_stop\"")
  }

  private func run(
    plan: ProductM2TestControlPlan
  ) async throws -> (ProductM2ConnectReport, ProductM2TestTrace) {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let dependencies = productM2TestDependencies(
      snapshot: fixture.snapshot,
      trace: trace,
      plan: plan
    )
    let report = await ProductM2ConnectOnceCoordinator(dependencies: dependencies).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: m2TestBudget()
    )
    return (report, trace)
  }
}
