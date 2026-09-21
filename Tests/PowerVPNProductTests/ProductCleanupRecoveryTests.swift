import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductCleanupRecoveryTests {
  @Test func currentProfileColdBaselineCommitsWhileMutationLeaseIsHeld() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = RecoveryTrace()
    let leaseState = RecoveryLeaseState()
    let runtime = recoveryRuntime(
      fixture: fixture,
      trace: trace,
      leaseState: leaseState,
      preflight: safeRecoveryPreflight
    )

    let report = await runtime.run(recoveryRequest) { report in
      trace.recordCommit(leaseHeld: leaseState.held)
      return report.permitsReconnect
    }

    #expect(report.outcome == .recovered)
    #expect(report.failure == nil)
    #expect(report.basis == .currentProfileColdBaseline)
    #expect(report.permitsReconnect)
    #expect(!report.originalCleanupRestored)
    #expect(report.authorizationClose == .accepted)
    #expect(report.authorizationOwnedMaterialErased)
    #expect(report.captureAttemptCount == 2)
    #expect(report.preflightSafe)
    #expect(report.captureAssessment?.passed == true)
    #expect(trace.captureWindowIDs.count == 2)
    #expect(Set(trace.captureWindowIDs).count == 1)
    #expect(trace.commitCount == 1)
    #expect(trace.leaseHeldDuringCommit)
    let closeIndex = try #require(trace.events.firstIndex(of: "close"))
    let captureIndex = try #require(trace.events.firstIndex(of: "capture"))
    #expect(closeIndex < captureIndex)
    #expect(!trace.events.contains("start"))
    #expect(!trace.events.contains("stop"))
    #expect(!trace.events.contains("ssh"))

    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
    #expect(json.contains("\"basis\":\"current_profile_cold_baseline\""))
    #expect(json.contains("\"originalCleanupRestored\":false"))
    #expect(!json.contains("Campus NC"))
    #expect(!json.contains("thu21"))
    #expect(!json.contains(String(repeating: "a", count: 64)))
  }

  @Test func unsafePreflightRejectsAndNeverCommits() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = RecoveryTrace()
    let runtime = recoveryRuntime(
      fixture: fixture,
      trace: trace,
      leaseState: RecoveryLeaseState(),
      preflight: unsafeRecoveryPreflight
    )

    let report = await runtime.run(recoveryRequest) { _ in
      trace.recordCommit(leaseHeld: true)
      return true
    }

    #expect(report.outcome == .rejected)
    #expect(report.failure == .preflightRejected)
    #expect(!report.preflightSafe)
    #expect(!report.permitsReconnect)
    #expect(report.captureAssessment == nil)
    #expect(!trace.events.contains("acquire"))
    #expect(!trace.events.contains("capture"))
    #expect(trace.commitCount == 0)
  }

  @Test func failedReceiptCommitReturnsRejectedWithoutReclassifyingMeasurement() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = RecoveryTrace()
    let leaseState = RecoveryLeaseState()
    let runtime = recoveryRuntime(
      fixture: fixture,
      trace: trace,
      leaseState: leaseState,
      preflight: safeRecoveryPreflight
    )

    let report = await runtime.run(recoveryRequest) { _ in
      trace.recordCommit(leaseHeld: leaseState.held)
      return false
    }

    #expect(report.outcome == .rejected)
    #expect(report.failure == .receiptPersistenceRejected)
    #expect(!report.permitsReconnect)
    #expect(!report.originalCleanupRestored)
    #expect(report.captureAssessment?.passed == true)
    #expect(report.preflightSafe)
    #expect(trace.commitCount == 1)
    #expect(trace.leaseHeldDuringCommit)
  }

  @Test func helperGenerationChangeDuringAuthorizationNeverCommitsRecovery() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = RecoveryTrace()
    let runtime = recoveryRuntime(
      fixture: fixture,
      trace: trace,
      leaseState: RecoveryLeaseState(),
      preflight: safeRecoveryPreflight,
      initialGeneration: VendorHelperGenerationSnapshot(
        launchdObserved: true, running: false, inactiveConfirmed: true,
        activeCount: 0, pid: nil, runs: 18)
    )

    let report = await runtime.run(recoveryRequest) { _ in
      trace.recordCommit(leaseHeld: true)
      return true
    }

    #expect(report.outcome == .rejected)
    #expect(report.failure == .coldBaselineRejected)
    #expect(report.captureAssessment?.initialHelperGenerationMatches == false)
    #expect(!report.permitsReconnect)
    #expect(trace.commitCount == 0)
  }

  @Test func cancellationDuringInitialObservationNeverAcquiresAuthorization() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = RecoveryTrace()
    let runtime = recoveryRuntime(
      fixture: fixture,
      trace: trace,
      leaseState: RecoveryLeaseState(),
      preflight: safeRecoveryPreflight,
      cancelDuringInitialObservation: true
    )

    let report = await Task { await runtime.run(recoveryRequest) { _ in true } }.value

    #expect(report.failure == .cancelled)
    #expect(!report.permitsReconnect)
    #expect(!trace.events.contains("acquire"))
    #expect(trace.commitCount == 0)
  }

  @Test func cancellationAtCommitBoundaryIsReportedAsCancelled() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = RecoveryTrace()
    let runtime = recoveryRuntime(
      fixture: fixture,
      trace: trace,
      leaseState: RecoveryLeaseState(),
      preflight: safeRecoveryPreflight
    )

    let report = await Task {
      await runtime.run(recoveryRequest) { _ in
        withUnsafeCurrentTask { $0?.cancel() }
        return false
      }
    }.value

    #expect(report.failure == .cancelled)
    #expect(!report.permitsReconnect)
    #expect(report.captureAssessment?.passed == true)
  }
}

private let recoveryRequest = ProductCleanupRecoveryRequest(
  resourceDisplayName: "Campus NC",
  sshTarget: .thu21
)

private func recoveryRuntime(
  fixture: AuthenticatedSnapshotFixture,
  trace: RecoveryTrace,
  leaseState: RecoveryLeaseState,
  preflight: VendorXPCPreflightEvidence,
  initialGeneration: VendorHelperGenerationSnapshot = m2ColdGeneration,
  cancelDuringInitialObservation: Bool = false
) -> ProductCleanupRecoveryRuntime {
  let authorizationState = AuthorizationLeaseTestState()
  let authorizationLease = testAuthorizationLease(
    snapshot: fixture.snapshot,
    state: authorizationState,
    onClose: { trace.record("close") }
  )
  let attempt = productM2AuthorizationAttempt(
    authorizationLease,
    trace: ProductM2TestTrace()
  )
  let snapshot = m2CaptureSnapshotFixture(
    effectiveSelectedRoute: .observed(selectedRouteToken: nil)
  )
  return ProductCleanupRecoveryRuntime(
    dependencies: ProductCleanupRecoveryDependencies(
      acquireMutationLease: { RecoveryMutationLease(state: leaseState) },
      beginAuthorization: { _ in
        trace.record("acquire")
        return attempt
      },
      observeGeneration: { _ in
        if cancelDuringInitialObservation { withUnsafeCurrentTask { $0?.cancel() } }
        return initialGeneration
      },
      captureNetwork: { window, routes, _ in
        #expect(routes.permitsIPv4(ProductM2SSHTarget.thu21.requiredTargetIPv4))
        trace.recordCapture(window)
        return snapshot
      },
      checkPreflight: { generation, _ in
        #expect(generation.exactInactive)
        trace.record("preflight")
        return preflight
      }
    )
  )
}

private let safeRecoveryPreflight = VendorXPCPreflightEvidence(
  guiProcessAbsent: true,
  helperProcessAbsent: true,
  otherVendorHelperProcessesAbsent: true,
  helperLaunchdInactive: true,
  dnsRecoveryFileAbsent: true,
  vendorLogRotationSafe: true
)

private let unsafeRecoveryPreflight = VendorXPCPreflightEvidence(
  guiProcessAbsent: true,
  helperProcessAbsent: true,
  otherVendorHelperProcessesAbsent: true,
  helperLaunchdInactive: true,
  dnsRecoveryFileAbsent: false,
  vendorLogRotationSafe: true
)

private final class RecoveryLeaseState: @unchecked Sendable {
  private let lock = NSLock()
  private var value = false
  var held: Bool { lock.withLock { value } }
  func set(_ value: Bool) { lock.withLock { self.value = value } }
}

private final class RecoveryMutationLease: ProductMutationLeaseHolding, @unchecked Sendable {
  private let state: RecoveryLeaseState
  init(state: RecoveryLeaseState) {
    self.state = state
    state.set(true)
  }
  deinit { state.set(false) }
}

private final class RecoveryTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedEvents: [String] = []
  private var windows: [ObjectIdentifier] = []
  private var commits = 0
  private var committedWithLease = false

  func record(_ event: String) { lock.withLock { storedEvents.append(event) } }
  func recordCapture(_ window: NetworkCleanupCaptureWindow) {
    lock.withLock {
      storedEvents.append("capture")
      windows.append(ObjectIdentifier(window))
    }
  }
  func recordCommit(leaseHeld: Bool) {
    lock.withLock {
      commits += 1
      committedWithLease = leaseHeld
    }
  }
  var events: [String] { lock.withLock { storedEvents } }
  var captureWindowIDs: [ObjectIdentifier] { lock.withLock { windows } }
  var commitCount: Int { lock.withLock { commits } }
  var leaseHeldDuringCommit: Bool { lock.withLock { committedWithLease } }
}
