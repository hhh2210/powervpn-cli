import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct UserProductRecoveryCommandTests {
  @Test func legacyV1FailureDecodesWithoutInventingRecovery() throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let sessionID = UUID().uuidString.lowercased()
    let data = Data(
      """
      {"schemaVersion":1,"sessionID":"\(sessionID)","target":"thu21","controlPath":"/tmp/powervpn-test.sock","phase":"failed","ownerPID":51342,"cleanupVerified":false,"failure":"cleanup_unproven"}
      """.utf8)
    let path = directory.appendingPathComponent("session.json")
    try data.write(to: path)
    #expect(chmod(path.path, 0o600) == 0)

    let loaded = try UserProductSessionStateStore(directory: directory).load()
    let state = try #require(loaded)
    #expect(state.schemaVersion == 1)
    #expect(state.cleanupVerified == false)
    #expect(state.failure == "cleanup_unproven")
    #expect(state.originalCleanupReceipt == nil)
    #expect(state.recoveryReceipt == nil)
    #expect(!state.reconnectPermitted)
  }

  @Test func clearPreservesOriginalFailureAndPersistsOneBoundReceipt() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let original = quarantinedRecoveryState()
    try store.save(original)
    let dependencies = recoveryDependencies(store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"],
      dependencies: dependencies
    )

    #expect(result.exitCode == 0)
    #expect(result.standardError.isEmpty)
    let loaded = try store.load()
    let state = try #require(loaded)
    let receipt = try #require(state.recoveryReceipt)
    let loadedArchive = try store.loadRecoveryArchive(sessionID: original.sessionID)
    let archive = try #require(loadedArchive)
    #expect(state.cleanupVerified == false)
    #expect(state.failure == "cleanup_unproven")
    #expect(state.reconnectPermitted)
    #expect(receipt.permitsReconnect)
    #expect(!receipt.originalCleanupRestored)
    #expect(receipt.basis == "current_profile_cold_baseline")
    #expect(archive.originalCleanupVerified == false)
    #expect(archive.originalFailure == "cleanup_unproven")
    #expect(archive.recoveryReceipt.measurementID == receipt.measurementID)
    #expect(result.standardOutput.contains(receipt.measurementID))
    #expect(!result.standardOutput.contains(original.controlPath))
    var archiveMetadata = stat()
    #expect(
      lstat(store.recoveryArchivePath(sessionID: original.sessionID), &archiveMetadata) == 0)
    #expect(archiveMetadata.st_mode & 0o777 == 0o600)

    let doctor = try await runCurrentMachineUserProductCommand(
      ["doctor", "--json"], dependencies: dependencies)
    #expect(doctor.exitCode == 0)
    #expect(doctor.standardOutput.contains("\"previousCleanupVerified\" : false"))
    #expect(doctor.standardOutput.contains("\"recoveryVerified\" : true"))
    #expect(doctor.standardOutput.contains("current_profile_cold_baseline"))
  }

  @Test func inspectNeverClearsQuarantineAndClearIsIdempotent() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let original = quarantinedRecoveryState()
    try store.save(original)
    let counter = RecoveryInvocationCounter()
    let dependencies = recoveryDependencies(store: store, counter: counter)

    let inspection = try await runCurrentMachineUserProductCommand(
      ["recovery", "inspect", "--json"], dependencies: dependencies)
    #expect(inspection.exitCode == 0)
    #expect(inspection.standardOutput.contains("measurement_passed"))
    #expect(inspection.standardOutput.contains("\"quarantineCleared\" : false"))
    #expect(inspection.standardOutput.contains("\"requiresHumanAction\" : true"))
    #expect(inspection.standardOutput.contains("powervpn recovery clear --json"))
    #expect(!inspection.standardOutput.contains("\"recoveryReceipt\""))
    #expect(try store.load()?.recoveryReceipt == nil)
    #expect(try store.loadRecoveryArchive(sessionID: original.sessionID) == nil)

    let doctorAfterInspect = try await runCurrentMachineUserProductCommand(
      ["doctor", "--json"], dependencies: dependencies)
    #expect(doctorAfterInspect.exitCode == 2)
    #expect(doctorAfterInspect.standardOutput.contains("previous_cleanup_unverified"))

    let first = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"], dependencies: dependencies)
    let persistedID = try #require(store.load()?.recoveryReceipt?.measurementID)
    let second = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"], dependencies: dependencies)
    #expect(first.exitCode == 0)
    #expect(second.exitCode == 0)
    #expect(second.standardOutput.contains("already_recovered"))
    #expect(second.standardOutput.contains(persistedID))
    #expect(counter.value == 2)
  }

  @Test func activeMasterAndUnknownCleanupNeverInvokeRecovery() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    var unknown = quarantinedRecoveryState()
    unknown.cleanupVerified = nil
    unknown.failure = "cleanup_receipt_missing"
    try store.save(unknown)
    let counter = RecoveryInvocationCounter()
    let dependencies = recoveryDependencies(
      store: store,
      counter: counter,
      masterExitCode: 0
    )

    let clear = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"], dependencies: dependencies)
    #expect(clear.exitCode == 74)
    #expect(clear.standardOutput.contains("session_active"))
    #expect(counter.value == 0)

    let doctor = try await runCurrentMachineUserProductCommand(
      ["doctor", "--json"], dependencies: dependencies)
    #expect(doctor.exitCode == 2)
    #expect(doctor.standardOutput.contains("previous_cleanup_unverified"))
    #expect(doctor.standardOutput.contains("\"sessionCleanupSafe\" : false"))
  }

  @Test func failedSessionProxyPersistsExactOriginalCleanupDimensions() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu21",
      controlPath: "/Users/test/.ssh/powervpn-receipt.sock",
      phase: .connected,
      ownerPID: 9_123
    )
    try store.save(state)
    let evidence = ProductM2CleanupEvidence(
      defaultRouteRestored: true,
      dnsRestored: false,
      interfacesRestored: true,
      utunRestored: true,
      persistentRoutesRestored: true,
      selectedRouteResidueCount: 0,
      surgeStateRestored: true,
      vendorProcessesRestored: true,
      helperGenerationRestored: true,
      structuralRouteTablesEqual: true
    )
    let shutdown = ProductPersistentTunnelShutdownReport(
      state: .stopped,
      cleanupPath: .cleanupUnproven,
      stopOutcome: .connectionInvalid,
      emergencyStopOutcome: .notAttempted,
      authorizationClose: .accepted,
      authorizationOwnedMaterialErased: true,
      cleanupEvidence: evidence,
      cleanupVerified: false,
      cleanupCaptureState: .measuredComplete,
      cleanupCaptureAttemptCount: 1
    )
    let dependencies = recoveryDependencies(store: store)
    let result = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", state.sessionID, "thu21", "192.0.2.21", "22"],
      dependencies: UserProductCommandDependencies(
        loadConfiguration: recoveryConfiguration,
        processRunner: RecoveryCommandProcessRunner(exitCode: 255),
        stateStore: store,
        executablePath: "/Users/test/.local/bin/powervpn",
        mutationLeaseAvailable: { true },
        systemStatus: recoverySystemStatus,
        proxyRunner: { _ in
          ProxyCommandResult(
            standardOutput: "",
            standardError: "cleanup_unproven\n",
            exitCode: 74,
            cleanupReceipt: shutdown
          )
        },
        recoveryRunner: dependencies.recoveryRunner,
        credentialFileSafe: { true },
        helperArtifactSafe: { true },
        vendorLogSafe: { true },
        cleanupPollLimit: 1
      )
    )

    #expect(result.exitCode == 74)
    let loaded = try store.load()
    let persisted = try #require(loaded)
    #expect(persisted.schemaVersion == 2)
    #expect(persisted.cleanupVerified == false)
    #expect(persisted.failure == "cleanup_unproven")
    #expect(persisted.originalCleanupReceipt?.cleanupVerified == false)
    #expect(persisted.originalCleanupReceipt?.cleanupEvidence.dnsRestored == false)
    #expect(persisted.originalCleanupReceipt?.cleanupEvidence.defaultRouteRestored == true)
  }

  @Test func preMutationOpenFailureDoesNotCreateCleanupQuarantine() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu21",
      controlPath: "/Users/test/.ssh/powervpn-early-failure.sock",
      phase: .connected
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
      proxyRunner: { _ in
        ProxyCommandResult(
          standardOutput: "",
          standardError: "tunnel_open_failed:preflight_blocked\n",
          exitCode: 69
        )
      },
      recoveryRunner: base.recoveryRunner,
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogSafe: { true },
      signalMonitorFactory: { RecoveryNoopSignalMonitor() },
      cleanupPollLimit: 1
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", state.sessionID, "thu21", "192.0.2.21", "22"],
      dependencies: dependencies
    )
    #expect(result.exitCode == 69)
    let loaded = try store.load()
    let persisted = try #require(loaded)
    #expect(persisted.cleanupVerified == true)
    #expect(persisted.originalCleanupReceipt == nil)
    #expect(persisted.reconnectPermitted)
  }

  @Test func upAcceptsRecoveredStateButKeepsRecoveryArchive() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let original = quarantinedRecoveryState()
    try store.save(original)
    let recoveryDependencies = recoveryDependencies(store: store)
    let clear = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"], dependencies: recoveryDependencies)
    #expect(clear.exitCode == 0)
    let loadedArchive = try store.loadRecoveryArchive(sessionID: original.sessionID)
    let archived = try #require(loadedArchive)

    let runner = RecoveryUpProcessRunner()
    let upDependencies = UserProductCommandDependencies(
      loadConfiguration: recoveryConfiguration,
      processRunner: runner,
      stateStore: store,
      executablePath: "/Users/test/.local/bin/powervpn",
      mutationLeaseAvailable: { true },
      systemStatus: recoverySystemStatus,
      proxyRunner: { _ in
        ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
      },
      recoveryRunner: recoveryDependencies.recoveryRunner,
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogSafe: { true },
      cleanupPollLimit: 1
    )
    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"], dependencies: upDependencies)

    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("Session: active"))
    let loadedState = try store.load()
    let current = try #require(loadedState)
    #expect(current.phase == .connected)
    #expect(current.failure == nil)
    #expect(current.recoveryReceipt == nil)
    #expect(try store.loadRecoveryArchive(sessionID: original.sessionID) == archived)
  }

  @Test func failedMasterLaunchNeverTreatsFreeMutationLeaseAsCleanupProof() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let dependencies = UserProductCommandDependencies(
      loadConfiguration: recoveryConfiguration,
      processRunner: RecoveryFailedUpProcessRunner(),
      stateStore: store,
      executablePath: "/Users/test/.local/bin/powervpn",
      mutationLeaseAvailable: { true },
      systemStatus: recoverySystemStatus,
      proxyRunner: { _ in
        ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
      },
      recoveryRunner: recoveryDependencies(store: store).recoveryRunner,
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogSafe: { true },
      cleanupPollLimit: 1
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"], dependencies: dependencies)
    #expect(result.exitCode == 69)
    let loaded = try store.load()
    let state = try #require(loaded)
    #expect(state.phase == .failed)
    #expect(state.cleanupVerified == false)
    #expect(state.failure == "ssh_master_start_cleanup_unverified")
  }

  @Test func doctorDoesNotMisclassifyActiveSessionAsPreviousCleanupFailure() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(
      UserProductSessionState(
        sessionID: UUID().uuidString.lowercased(),
        target: "thu21",
        controlPath: "/Users/test/.ssh/powervpn-active.sock",
        phase: .connected,
        ownerPID: 4_321
      ))
    let result = try await runCurrentMachineUserProductCommand(
      ["doctor", "--json"], dependencies: recoveryDependencies(store: store))

    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("\"sessionCleanupSafe\" : true"))
    #expect(!result.standardOutput.contains("previous_cleanup_unverified"))
  }

  @Test func statusCannotQuarantineConnectingSessionWhileCommandLockIsHeld() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu21",
      controlPath: "/Users/test/.ssh/powervpn-connecting.sock",
      phase: .connecting
    )
    try store.save(state)
    let lock = try store.acquireCommandLock()

    let result = try await runCurrentMachineUserProductCommand(
      ["status", "--json"],
      dependencies: recoveryDependencies(store: store)
    )
    withExtendedLifetime(lock) {}

    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("\"state\" : \"connecting\""))
    #expect(try store.load() == state)
  }

  @Test func visibleSessionCommitSurvivesDirectorySyncErrorWithoutDeletingArchive() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let sync = RecoveryDirectorySyncScript([true, false])
    let store = UserProductSessionStateStore(
      directory: directory,
      directorySync: sync.call
    )
    let original = quarantinedRecoveryState()
    try store.save(original)

    let result = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"],
      dependencies: recoveryDependencies(store: store)
    )

    #expect(result.exitCode == 0)
    let loadedState = try store.load()
    let state = try #require(loadedState)
    let loadedArchive = try store.loadRecoveryArchive(sessionID: original.sessionID)
    let archive = try #require(loadedArchive)
    #expect(state.recoveryReceipt?.permitsReconnect == true)
    #expect(archive.recoveryReceipt == state.recoveryReceipt)
    #expect(result.standardOutput.contains(archive.recoveryReceipt.measurementID))
  }

  @Test func signalCancelsRecoveryAndLeavesQuarantineUnchanged() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let original = quarantinedRecoveryState()
    try store.save(original)
    let base = recoveryDependencies(store: store)
    let monitor = RecoverySignalMonitor()
    let gate = RecoveryCancellationGate()
    let dependencies = UserProductCommandDependencies(
      loadConfiguration: recoveryConfiguration,
      processRunner: RecoveryCommandProcessRunner(exitCode: 255),
      stateStore: store,
      executablePath: "/Users/test/.local/bin/powervpn",
      mutationLeaseAvailable: { true },
      systemStatus: recoverySystemStatus,
      proxyRunner: base.proxyRunner,
      recoveryRunner: { request, _, commit in
        gate.waitForCancellation()
        return await syntheticRecoveryMeasurement(request: request, commit: commit)
      },
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogSafe: { true },
      signalMonitorFactory: { monitor },
      cleanupPollLimit: 1
    )

    let command = Task {
      try await runCurrentMachineUserProductCommand(
        ["recovery", "clear", "--json"], dependencies: dependencies)
    }
    #expect(gate.waitUntilStarted())
    monitor.trigger()
    let result = try await command.value

    #expect(result.exitCode == 130)
    #expect(result.standardOutput.contains("\"outcome\" : \"cancelled\""))
    #expect(result.standardOutput.contains("\"requiresHumanAction\" : true"))
    #expect(try store.load() == original)
    #expect(try store.loadRecoveryArchive(sessionID: original.sessionID) == nil)
  }

  @Test func contradictoryPersistedRecoveryBooleansFailClosed() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let clear = try await runCurrentMachineUserProductCommand(
      ["recovery", "clear", "--json"], dependencies: recoveryDependencies(store: store))
    #expect(clear.exitCode == 0)

    let data = try Data(contentsOf: URL(fileURLWithPath: store.statePath))
    let object = try JSONSerialization.jsonObject(with: data)
    var root = try #require(object as? [String: Any])
    var receipt = try #require(root["recoveryReceipt"] as? [String: Any])
    var evidence = try #require(receipt["evidence"] as? [String: Any])
    evidence["capturesComplete"] = false
    evidence["passed"] = true
    receipt["evidence"] = evidence
    root["recoveryReceipt"] = receipt
    let corrupted = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
    try corrupted.write(to: URL(fileURLWithPath: store.statePath), options: .atomic)
    #expect(chmod(store.statePath, 0o600) == 0)

    #expect(throws: UserProductSessionStoreError.invalidState) {
      _ = try store.load()
    }
  }
}
