import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2CleanupCaptureTests {
  @Test func snapshotClassifierSeparatesRetryableAndTerminalStates() throws {

    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2ExitedGeneration,
          helperObservationState: .changedDuringCapture
        )) == .changedDuringCapture)
    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2UnavailableGeneration,
          helperObservationState: .changedDuringCapture
        )) == .generationNotExact)
    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2ExitedGeneration,
          defaultRoute: .unavailable(.outputTooLarge)
        )) == .outputTooLarge)
    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2ExitedGeneration,
          defaultRoute: .unavailable(.invalidOutput)
        )) == .invalidOutput)
    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2UnavailableGeneration
        )) == .generationNotExact)
    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2ExitedGeneration,
          vendorProcesses: m2VendorProcessesFixture(ipsecProcessCount: 1)
        )) == .vendorProcessResidue)

    #expect(
      classifyCleanupCapture(
        m2CaptureSnapshotFixture(
          helperGeneration: m2ExitedGeneration,
          vendorProcesses: m2InconsistentVendorProcesses
        )) == .structuralInconsistency)
  }
  @Test func changedCaptureNeverHidesPrimitiveFailureOrObservedInvariant() async throws {
    guard
      let before = m2ObservedNetworkBaseline(
        generation: m2ColdGeneration
      ).snapshot
    else {
      preconditionFailure("observed baseline fixture lost its snapshot")
    }
    let cases: [(ProductM2CleanupCaptureAttempt, ProductM2CleanupCaptureState)] = [
      (
        ProductM2CleanupCaptureAttempt(
          before: before,
          after: m2CaptureSnapshotFixture(
            helperGeneration: m2ExitedGeneration,
            helperObservationState: .changedDuringCapture,
            vendorProcesses: m2InconsistentVendorProcesses
          ),
          startRequestSent: true
        ),
        .structuralInconsistency
      ),
      (
        effectiveRouteFailureAttempt(.commandFailed, before: before),
        .commandFailed
      ),
      (
        effectiveRouteFailureAttempt(.outputTooLarge, before: before),
        .outputTooLarge
      ),
      (
        effectiveRouteFailureAttempt(.invalidOutput, before: before),
        .invalidOutput
      ),
    ]

    for (attempt, expectedState) in cases {
      let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
      defer { fixture.erase() }
      let trace = ProductM2TestTrace()
      let report = await ProductM2ConnectOnceCoordinator(
        dependencies: productM2TestDependencies(
          snapshot: fixture.snapshot,
          trace: trace,
          cleanupAttempts: [attempt, .measured(m2CompleteCleanup)]
        )
      ).run(
        ProductM2ConnectRequest(
          resourceDisplayName: "Campus NC",
          sshTarget: .thu21
        ))

      #expect(attempt.state == expectedState)
      #expect(report.cleanupCaptureState == expectedState)
      #expect(report.cleanupCaptureRetryReason == nil)
      #expect(report.cleanupCaptureAttemptCount == 1)
      #expect(trace.count("verify") == 1)
      #expect(trace.count("route_disable") == 1)
      #expect(trace.count("stop") == 1)
      #expect(trace.count("logout") == 1)
    }
  }

  @Test(
    arguments: [
      ProductM2CleanupCaptureState.commandFailed,
      .outputTooLarge,
      .invalidOutput,
      .unavailable,
      .generationNotExact,
      .vendorProcessResidue,
      .structuralInconsistency,
    ])
  func terminalCaptureStateNeverRetries(
    _ terminalState: ProductM2CleanupCaptureState
  ) async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [
          ProductM2CleanupCaptureAttempt(
            evidence: .unavailable,
            state: terminalState,
            captureInvoked: true
          ),
          .measured(m2CompleteCleanup),
        ]
      )
    ).run(
      ProductM2ConnectRequest(
        resourceDisplayName: "Campus NC",
        sshTarget: .thu21
      ))

    #expect(!report.cleanupVerified)
    #expect(report.cleanupCaptureState == terminalState)
    #expect(report.cleanupCaptureRetryReason == nil)
    #expect(report.cleanupCaptureAttemptCount == 1)
    #expect(!report.cleanupEvidence.complete)
    #expect(!report.cleanupEvidence.defaultRouteRestored)
    #expect(trace.count("verify") == 1)
    #expect(trace.count("route_disable") == 1)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
  }
}

private func classifyCleanupCapture(
  _ after: NetworkCleanupSnapshot
) -> ProductM2CleanupCaptureState {
  guard
    let before = m2ObservedNetworkBaseline(
      generation: m2ColdGeneration
    ).snapshot
  else {
    preconditionFailure("observed baseline fixture lost its snapshot")
  }
  return ProductM2CleanupCaptureAttempt(
    before: before,
    after: after,
    startRequestSent: true
  ).state
}

private func effectiveRouteFailureAttempt(
  _ state: NetworkCleanupObservationState,
  before: NetworkCleanupSnapshot
) -> ProductM2CleanupCaptureAttempt {
  ProductM2CleanupCaptureAttempt(
    before: before,
    after: m2CaptureSnapshotFixture(
      helperGeneration: m2ExitedGeneration,
      helperObservationState: .changedDuringCapture,
      effectiveSelectedRoute: .unavailable(state)
    ),
    startRequestSent: true
  )
}

private let m2InconsistentVendorProcesses = NetworkCleanupVendorProcessSnapshot(
  fingerprint: .observed(
    count: 1,
    sha256: String(repeating: "a", count: 64)
  ),
  officialGUIProcessCount: 0,
  charonProcessCount: 0,
  ipsecProcessCount: 0,
  shellProcessCount: 0,
  identityTokens: []
)
