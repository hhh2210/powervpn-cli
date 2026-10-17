import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct ProductPersistentTunnelOpenReceiptTests {
  @Test func mutatedOpenFailurePersistsExactCleanupReceiptInSessionState() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let evidence = ProductM2CleanupEvidence(
      defaultRouteRestored: true,
      dnsRestored: false,
      interfacesRestored: true,
      utunRestored: true,
      persistentRoutesRestored: true,
      selectedRouteResidueCount: 0,
      surgeStateRestored: true,
      vendorProcessesRestored: true,
      helperGenerationRestored: false,
      structuralRouteTablesEqual: true
    )
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .noLease(generation: m2UnavailableGeneration),
        cleanup: evidence
      ))
    let proxyOpen = await openProductProxyTunnel(
      runtime: runtime,
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: m2TestBudget()
    )
    guard case .failed(let openFailure) = proxyOpen else {
      Issue.record("mutated failed open unexpectedly returned a lease")
      return
    }
    #expect(openFailure.helperMutationRequested)
    #expect(!openFailure.cleanupVerified)
    #expect(openFailure.cleanupReceipt?.cleanupEvidence == evidence)

    let commandResult = try await runProxySSHCommand(
      [
        "proxy", "ssh", "--resource-display-name", "Campus NC",
        "--ssh-target", "thu21", "192.0.2.21", "22", "--non-interactive",
      ],
      authorizationAvailabilityFailure: { nil },
      resolveTarget: { _ in .thu21 },
      runtime: { _, _ in proxyOpen }
    )
    #expect(commandResult.exitCode == 74)
    #expect(commandResult.cleanupReceipt?.cleanupEvidence == evidence)

    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu21",
      controlPath: "/Users/test/.ssh/powervpn-open-receipt.sock",
      phase: .connecting
    )
    try store.save(state)
    let base = recoveryDependencies(store: store)
    let dependencies = UserProductCommandDependencies(
      loadConfiguration: recoveryConfiguration,
      processRunner: RecoveryCommandProcessRunner(exitCode: 255),
      stateStore: store,
      executablePath: "/Users/test/.local/bin/powervpn",
      mutationLeaseAvailable: { true },
      systemStatus: recoverySystemStatus,
      proxyRunner: { _ in commandResult },
      recoveryRunner: base.recoveryRunner,
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogFinding: { .bounded },
      signalMonitorFactory: { RecoveryNoopSignalMonitor() },
      cleanupPollLimit: 1
    )
    _ = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", state.sessionID, "thu21", "192.0.2.21", "22"],
      dependencies: dependencies
    )
    let loaded = try store.load()
    let persisted = try #require(loaded)
    #expect(persisted.cleanupVerified == false)
    #expect(persisted.failure == "cleanup_unproven")
    #expect(persisted.originalCleanupReceipt?.cleanupEvidence == .init(evidence))
  }

  @Test func unmutatedOpenFailureWithUnusableCleanupCaptureLeavesNoQuarantine() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Other NC"]))
    defer { fixture.erase() }
    let trace = ProductM2TestTrace()
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanupAttempts: [
          ProductM2CleanupCaptureAttempt(
            evidence: .unavailable, state: .invalidOutput, captureInvoked: true)
        ]
      ))
    let proxyOpen = await openProductProxyTunnel(
      runtime: runtime,
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: m2TestBudget()
    )
    guard case .failed(let openFailure) = proxyOpen else {
      Issue.record("unmatched resource unexpectedly returned a lease")
      return
    }
    #expect(openFailure.failure == .resourceNotFound)
    #expect(!openFailure.helperMutationRequested)
    #expect(openFailure.cleanupVerified)
    #expect(openFailure.cleanupReceipt == nil)
    #expect(trace.count("begin_start") == 0)

    let commandResult = try await runProxySSHCommand(
      [
        "proxy", "ssh", "--resource-display-name", "Campus NC",
        "--ssh-target", "thu21", "192.0.2.21", "22", "--non-interactive",
      ],
      authorizationAvailabilityFailure: { nil },
      resolveTarget: { _ in .thu21 },
      runtime: { _, _ in proxyOpen }
    )
    #expect(commandResult.exitCode == 69)
    #expect(commandResult.cleanupReceipt == nil)

    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu21",
      controlPath: "/Users/test/.ssh/powervpn-open-receipt.sock",
      phase: .connecting
    )
    try store.save(state)
    let base = recoveryDependencies(store: store)
    let dependencies = UserProductCommandDependencies(
      loadConfiguration: recoveryConfiguration,
      processRunner: RecoveryCommandProcessRunner(exitCode: 255),
      stateStore: store,
      executablePath: "/Users/test/.local/bin/powervpn",
      mutationLeaseAvailable: { true },
      systemStatus: recoverySystemStatus,
      proxyRunner: { _ in commandResult },
      recoveryRunner: base.recoveryRunner,
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogFinding: { .bounded },
      signalMonitorFactory: { RecoveryNoopSignalMonitor() },
      cleanupPollLimit: 1
    )
    _ = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", state.sessionID, "thu21", "192.0.2.21", "22"],
      dependencies: dependencies
    )
    let persisted = try #require(try store.load())
    #expect(persisted.phase == .failed)
    #expect(persisted.cleanupVerified == true)
    #expect(persisted.failure != "cleanup_unproven")
    #expect(persisted.originalCleanupReceipt == nil)
    #expect(persisted.reconnectPermitted)
  }

  @Test func shutdownReceiptKeepsTheRealControlPathWhenVerificationFails() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: ProductM2TestTrace(),
        cleanup: .unavailable
      ))
    let opened = await runtime.open(
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      startupBudget: m2TestBudget()
    )
    guard case .opened(let lease, _) = opened else {
      Issue.record("persistent tunnel did not open")
      return
    }

    let report = await lease.shutdown(budget: .start())
    #expect(!report.cleanupVerified)
    #expect(report.cleanupPath == .cleanupUnproven)
    #expect(report.controlCleanupPath == .sameLeaseStop)

    let receipt = UserProductOriginalCleanupReceipt(report)
    #expect(receipt.cleanupPath == "cleanup_unproven")
    #expect(receipt.controlCleanupPath == "same_lease_stop")
    #expect(receipt.valid)

    // Receipts persisted before the field existed still decode and validate.
    var object =
      try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any])
    #expect(object.removeValue(forKey: "controlCleanupPath") != nil)
    let legacy = try JSONDecoder().decode(
      UserProductOriginalCleanupReceipt.self,
      from: JSONSerialization.data(withJSONObject: object)
    )
    #expect(legacy.controlCleanupPath == nil)
    #expect(legacy.valid)
  }
}
