import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AbsoluteCoordinatorBudgetTests {
  @Test func workCutoffBeforeBeginStartNeverMutatesAndStillCleansAuthorization() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let snapshot = fixture.snapshot
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: snapshot,
        trace: trace,
        authorizationPrepare: { handle, target in
          clock.set(milliseconds: 65_000)
          return try ProductM2PortalAdapter.prepare(
            snapshot: snapshot,
            handle: handle,
            requiredTargetIPv4: target
          )
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(!report.helperMutationRequested)
    #expect(report.cleanupVerified)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 1)
  }

  @Test func submittedStartCrossingWorkCutoffFinishesInsteadOfStartingNewWork() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onAwaitStart: { clock.set(milliseconds: 65_000) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.finalState == .disconnected)
    #expect(report.helperMutationRequested)
    #expect(report.cleanupVerified)
    #expect(trace.count("begin_start") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("ssh") == 0)
  }

  @Test func expiredNilActiveCaptureReportsDeadlineInsteadOfActiveNetworkFailure() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace(
      baselines: [ProductM2NetworkBaseline(), ProductM2NetworkBaseline()]
    )
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onCaptureBaseline: { selectedRoutes, result, _ in
          if selectedRoutes != nil, result == nil {
            clock.set(milliseconds: 65_000)
          }
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(report.firstBadEvent != .activeNetworkUnproven)
    #expect(report.finalState == .disconnected)
    #expect(report.cleanupVerified)
  }

  @Test func startAndSSHReceiveOnlyTheRemainingWorkBudget() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let observation = ProductM2BudgetObservation()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onCaptureBaseline: { _, _, _ in
          let count = observation.recordCapture()
          if count == 2 { clock.set(milliseconds: 64_000) }
        },
        onProveFreshSSH: { deadline in
          observation.recordSSH(deadline.remainingMilliseconds(cappedAt: 15_000))
        },
        onBeginStart: observation.recordStart
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(observation.startTimeout == 1_000)
    #expect(observation.sshTimeout == 1_000)
  }

  @Test func cleanupStagesConsumeTheirOwnAbsoluteReservesInOrder() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let observation = ProductM2BudgetObservation()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onAuthorizationClose: { deadline in
          observation.recordAuthorization(
            deadline.remainingMilliseconds(cappedAt: 20_000))
          clock.set(milliseconds: 93_999)
        },
        onVerifyCleanup: { deadline in
          observation.recordVerification(
            deadline.remainingMilliseconds(cappedAt: 24_000))
          clock.set(milliseconds: 117_999)
        },
        onAwaitStart: { clock.set(milliseconds: 65_000) },
        onStop: { timeout in
          observation.recordStop(timeout)
          clock.set(milliseconds: 72_999)
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.cleanupVerified)
    #expect(report.finalState == .disconnected)
    #expect(observation.cleanup == ["stop:2000", "authorization:20000", "verify:24000"])
  }

  @Test func expiredReportCutoffOverridesSuccessButPreservesCleanupTruth() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        onVerifyCleanup: { _ in
          clock.enqueue(milliseconds: [117_999, 120_000])
        }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .deadlineExceeded)
    #expect(report.firstBadEvent == .deadlineExceeded)
    #expect(report.finalState == .disconnected)
    #expect(report.cleanupVerified)
    #expect(report.authorizationOwnedMaterialErased)
  }

  @Test func cleanupUnprovenRemainsHigherPriorityThanExpiredReportCutoff() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanup: .unavailable,
        onVerifyCleanup: { _ in clock.set(milliseconds: 120_000) }
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: budget
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(!report.cleanupVerified)
    #expect(report.firstBadEvent == .cleanupVerificationRejected)
  }
}

private final class ProductM2BudgetObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var captures = 0
  private var start: Int?
  private var ssh: Int?
  private var cleanupEvents: [String] = []

  func recordCapture() -> Int {
    lock.withLock {
      captures += 1
      return captures
    }
  }

  func recordStart(_ timeout: Int) { lock.withLock { start = timeout } }
  func recordSSH(_ timeout: Int?) { lock.withLock { ssh = timeout } }
  func recordStop(_ timeout: Int) {
    lock.withLock { cleanupEvents.append("stop:\(timeout)") }
  }
  func recordAuthorization(_ timeout: Int?) {
    lock.withLock { cleanupEvents.append("authorization:\(timeout ?? -1)") }
  }
  func recordVerification(_ timeout: Int?) {
    lock.withLock { cleanupEvents.append("verify:\(timeout ?? -1)") }
  }

  var startTimeout: Int? { lock.withLock { start } }
  var sshTimeout: Int? { lock.withLock { ssh } }
  var cleanup: [String] { lock.withLock { cleanupEvents } }
}
