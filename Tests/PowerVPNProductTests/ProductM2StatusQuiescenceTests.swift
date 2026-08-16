import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2StatusQuiescenceTests {
  @Test func lateStatusEventRestartsQuietWindowBeforeRouteActivation() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let statusEvents = ProductM2StatusEventCounter(1)
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        statusEventCountOperation: statusEvents.current
      ))
    let task = Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )
    }

    #expect(await waitForStatusWait(trace))
    let quiescenceStarted = ContinuousClock.now
    try await Task.sleep(for: .milliseconds(150))
    statusEvents.increment()
    #expect(trace.count("route_enable") == 0)
    #expect(await waitForRouteEnable(trace, timeout: .milliseconds(500)))
    let elapsed = quiescenceStarted.duration(to: ContinuousClock.now)
    #expect(elapsed >= .milliseconds(500))
    #expect(elapsed <= .milliseconds(650))

    let report = await task.value
    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.routeActivationAcknowledged)
  }

  @Test func stableConnectedStatusWaitsOneQuietWindowBeforeRouteActivation() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let statusEvents = ProductM2StatusEventCounter(1)
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        statusEventCountOperation: statusEvents.current
      ))
    let task = Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )
    }

    #expect(await waitForStatusWait(trace))
    let quiescenceStarted = ContinuousClock.now
    #expect(trace.count("route_enable") == 0)
    #expect(await waitForRouteEnable(trace, timeout: .milliseconds(650)))
    let elapsed = quiescenceStarted.duration(to: ContinuousClock.now)
    #expect(elapsed >= .milliseconds(350))
    #expect(elapsed <= .milliseconds(600))

    let report = await task.value
    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.routeActivationAcknowledged)
  }

  @Test func continuousStatusEventsHitWaitCapAndStillAttemptRouteActivation() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let statusEvents = ProductM2StatusEventCounter(1)
    let coordinator = ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        statusEventCountOperation: statusEvents.current
      ))
    let task = Task {
      await coordinator.run(
        ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
      )
    }

    #expect(await waitForStatusWait(trace))
    let quiescenceStarted = ContinuousClock.now
    let emitter = Task {
      for _ in 0..<8 {
        try? await Task.sleep(for: .milliseconds(90))
        statusEvents.increment()
      }
    }
    try await Task.sleep(for: .milliseconds(650))
    #expect(trace.count("route_enable") == 0)
    #expect(await waitForRouteEnable(trace, timeout: .milliseconds(350)))
    let elapsed = quiescenceStarted.duration(to: ContinuousClock.now)
    #expect(elapsed >= .milliseconds(750))
    #expect(elapsed <= .milliseconds(1_000))
    await emitter.value

    let report = await task.value
    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.routeActivationRequestSent)
    #expect(report.routeActivationAcknowledged)
  }

  @Test func ordinaryRouteAcknowledgementStillSucceedsAfterQuiescence() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let statusEvents = ProductM2StatusEventCounter(1)
    let startedAt = ContinuousClock.now
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        routeActivationCompletionSource: .ordinaryConnection,
        statusEventCountOperation: statusEvents.current
      )
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(startedAt.duration(to: ContinuousClock.now) >= .milliseconds(350))
    #expect(report.outcome == .connectedAndCleanedUp)
    #expect(report.vendorStatusEvidence.connectedProven)
    #expect(report.routeActivationAcknowledged)
    #expect(report.routeActivationPeerGenerationValidated)
    #expect(report.routeActivationCompletionSource == .ordinaryConnection)
    #expect(
      m2EventIndex("status_wait", in: trace.events)
        < m2EventIndex("route_enable", in: trace.events)
    )
  }
}

private final class ProductM2StatusEventCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count: Int

  init(_ count: Int) {
    self.count = count
  }

  func increment() {
    lock.withLock { count += 1 }
  }

  func current() -> Int {
    lock.withLock { count }
  }
}

private func waitForStatusWait(_ trace: ProductM2TestTrace) async -> Bool {
  await waitForTrace(timeout: .seconds(1)) {
    trace.count("status_wait") == 1
  }
}

private func waitForRouteEnable(
  _ trace: ProductM2TestTrace,
  timeout: Duration
) async -> Bool {
  await waitForTrace(timeout: timeout) {
    trace.count("route_enable") == 1
  }
}

private func waitForTrace(
  timeout: Duration,
  condition: @escaping @Sendable () -> Bool
) async -> Bool {
  let deadline = ContinuousClock.now.advanced(by: timeout)
  while !condition(), ContinuousClock.now < deadline {
    try? await Task.sleep(for: .milliseconds(5))
  }
  return condition()
}
