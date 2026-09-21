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
      vendorLogSafe: { true },
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
}
