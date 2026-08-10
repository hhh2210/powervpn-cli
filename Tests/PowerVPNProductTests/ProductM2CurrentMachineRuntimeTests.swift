import Foundation
import Testing

@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2CurrentMachineRuntimeTests {
  @Test func compositionIsInertAndRejectedPreflightStopsBeforeSideEffects() async {
    let trace = CurrentMachineRuntimeTrace()
    let coordinatorTrace = ProductM2TestTrace()
    let runtime = ProductM2CurrentMachineRuntime(
      controlRuntimePreflightAccepted: {
        trace.record("session_preflight")
        return true
      },
      generationObserver: CurrentMachineGenerationObserver(trace: trace),
      preflightChecker: CurrentMachinePreflightChecker(trace: trace, accepted: false),
      networkObserver: CurrentMachineNetworkObserver(trace: trace),
      authorizationProvider: ProductM2PortalAdapter { _ in
        trace.record("portal")
        fatalError("preflight rejection must not acquire native authorization")
      },
      control: productM2TestControl(trace: coordinatorTrace, plan: .acknowledged),
      freshSSHProver: ProductM2FreshSSHProver(
        homeDirectory: "/tmp",
        generateChallenge: { "00000000000000000000000000000000" },
        execute: { _, _ in
          trace.record("ssh")
          return ProductM2FreshSSHProcessResult(processStarted: false, exitStatus: nil)
        }
      )
    )

    #expect(trace.events.isEmpty)
    let report = await runtime.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: m2TestBudget()
    )

    #expect(report.outcome == .preflightBlocked)
    #expect(trace.events == ["session_preflight", "generation", "preflight"])
    #expect(trace.count("network") == 0)
    #expect(trace.count("portal") == 0)
    #expect(trace.count("ssh") == 0)
    #expect(coordinatorTrace.count("begin_start") == 0)
    #expect(coordinatorTrace.count("emergency_stop") == 0)
  }

  @Test func defaultVendorOnceProviderFailsBeforeNetworkPortalOrControl() async {
    let trace = CurrentMachineRuntimeTrace()
    let coordinatorTrace = ProductM2TestTrace()
    let runtime = ProductM2CurrentMachineRuntime(
      controlRuntimePreflightAccepted: {
        trace.record("session_preflight")
        return true
      },
      generationObserver: CurrentMachineGenerationObserver(trace: trace),
      preflightChecker: CurrentMachinePreflightChecker(trace: trace, accepted: true),
      networkObserver: CurrentMachineNetworkObserver(trace: trace),
      control: productM2TestControl(trace: coordinatorTrace, plan: .acknowledged),
      freshSSHProver: ProductM2FreshSSHProver(
        homeDirectory: "/tmp",
        generateChallenge: { "00000000000000000000000000000000" },
        execute: { _, _ in
          trace.record("ssh")
          return ProductM2FreshSSHProcessResult(processStarted: false, exitStatus: nil)
        }
      )
    )

    let report = await runtime.run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: m2TestBudget()
    )

    #expect(report.schemaVersion == 7)
    #expect(report.outcome == .authorizationAcquisitionRejected)
    #expect(report.firstBadEvent == .authorizationAcquisitionRejected)
    #expect(report.authorizationSource == .vendorOnce)
    #expect(report.authorizationAcquisition == .rejected)
    #expect(report.authorizationFailure == .providerUnavailable)
    #expect(report.authorizationOwnedMaterialErased)
    #expect(!report.serverContactRequested)
    #expect(!report.helperMutationRequested)
    #expect(runtime.authorizationAvailabilityFailure == .providerUnavailable)
    #expect(trace.events.isEmpty)
    #expect(trace.count("network") == 0)
    #expect(trace.count("ssh") == 0)
    #expect(coordinatorTrace.count("begin_start") == 0)
    #expect(coordinatorTrace.count("emergency_stop") == 0)
  }
}

private final class CurrentMachineRuntimeTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedEvents: [String] = []

  func record(_ event: String) { lock.withLock { storedEvents.append(event) } }
  var events: [String] { lock.withLock { storedEvents } }
  func count(_ event: String) -> Int {
    lock.withLock { storedEvents.count { $0 == event } }
  }
}

private struct CurrentMachineGenerationObserver: BoundedVendorHelperGenerationObserving {
  let trace: CurrentMachineRuntimeTrace

  func observe(timeoutMilliseconds: Int) async -> VendorHelperGenerationSnapshot {
    trace.record("generation")
    return m2ColdGeneration
  }
}

private struct CurrentMachinePreflightChecker: BoundedVendorXPCPreflightChecking {
  let trace: CurrentMachineRuntimeTrace
  let accepted: Bool

  func check(
    generation: VendorHelperGenerationSnapshot,
    timeoutMilliseconds: Int
  ) async -> VendorXPCPreflightEvidence {
    trace.record("preflight")
    return VendorXPCPreflightEvidence(
      guiProcessAbsent: accepted,
      helperProcessAbsent: true,
      otherVendorHelperProcessesAbsent: true,
      helperLaunchdInactive: generation.exactInactive,
      dnsRecoveryFileAbsent: true,
      vendorLogRotationSafe: true
    )
  }
}

private struct CurrentMachineNetworkObserver: NetworkCleanupObserving {
  let trace: CurrentMachineRuntimeTrace

  func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    timeoutMilliseconds: Int
  ) async -> NetworkCleanupSnapshot {
    trace.record("network")
    fatalError("preflight rejection must not capture network state")
  }
}
