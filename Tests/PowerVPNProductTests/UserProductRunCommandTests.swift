import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct UserProductRunCommandTests {
  @Test func runReusesActiveSessionAndPassesRemoteExitCode() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 42)
    try store.save(activeState(controlPath: ssh.socket))
    ssh.markAlive(ssh.socket)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "nvidia-smi", "-L"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 42)
    #expect(result.standardError.isEmpty)
    #expect(ssh.starts == 0)
    #expect(
      ssh.execs == [["-S", ssh.socket, "-o", "ControlMaster=no", "thu21", "nvidia-smi", "-L"]])
  }

  @Test func runStartsPersistentSessionThenExecutes() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 0)
    #expect(result.standardError.contains("powervpn run: session_started"))
    #expect(ssh.starts == 1)
    #expect(ssh.execs.count == 1)
    #expect(try store.load()?.phase == .connected)
  }

  @Test func runClearsMeasuredQuarantineBeforeStarting() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let counter = RecoveryInvocationCounter()
    let ssh = RunScriptedSSH(execExitCode: 0)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store, counter: counter)
    )

    #expect(result.exitCode == 0)
    #expect(counter.value == 1)
    #expect(result.standardError.contains("powervpn run: quarantine_cleared"))
    #expect(result.standardError.contains("powervpn run: session_started"))
    #expect(ssh.starts == 1)
    #expect(ssh.execs.count == 1)
  }

  @Test func runStopsForHumanWhenMeasuredRecoveryIsRejected() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let original = quarantinedRecoveryState()
    try store.save(original)
    let ssh = RunScriptedSSH(execExitCode: 0)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store, recoveryPasses: false)
    )

    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("powervpn run: recovery_rejected"))
    #expect(result.standardError.hasSuffix("next: powervpn recovery inspect --json\n"))
    #expect(ssh.starts == 0)
    #expect(ssh.execs.isEmpty)
    #expect(try store.load() == original)
  }

  @Test func runNamesTheVendorLogRepairWhenOnlyThatPreflightFails() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let rejection = ProductCleanupRecoveryReport(
      failure: .preflightRejected,
      source: .nativePortal,
      preflight: VendorXPCPreflightEvidence(
        guiProcessAbsent: true,
        helperProcessAbsent: true,
        otherVendorHelperProcessesAbsent: true,
        helperLaunchdInactive: true,
        dnsRecoveryFileAbsent: true,
        vendorLogRotationSafe: false,
        vendorLogFinding: .absent
      ),
      mutationLeaseAcquired: true
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, recoveryPasses: false, rejection: rejection)
    )

    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("local preflight failed (vendor_log_absent)"))
    #expect(result.standardError.hasSuffix("next: powervpn repair vendor-log --json\n"))
    #expect(ssh.starts == 0)
  }

  @Test func runRetriesIntermittentCatalogSelectionThenStarts() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter,
        rejection: ProductCleanupRecoveryReport(
          failure: .selectionRejected, source: .nativePortal, mutationLeaseAcquired: true),
        rejectionsBeforePass: 2)
    )

    #expect(counter.value == 3)
    #expect(result.standardError.contains("powervpn run: quarantine_cleared"))
    #expect(!result.standardError.contains("recovery_rejected"))
  }

  @Test func runStopsAfterThreeIntermittentSelectionFailures() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter,
        rejection: ProductCleanupRecoveryReport(
          failure: .selectionRejected, source: .nativePortal, mutationLeaseAcquired: true),
        rejectionsBeforePass: 5)
    )

    #expect(counter.value == 3)
    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("powervpn run: recovery_rejected"))
    #expect(ssh.starts == 0)
  }

  @Test func runRetriesColdBaselineFlakeThenStarts() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter, events: events,
        rejection: ProductCleanupRecoveryReport(
          failure: .coldBaselineRejected, source: .nativePortal, mutationLeaseAcquired: true),
        rejectionsBeforePass: 2)
    )

    #expect(result.exitCode == 0)
    #expect(counter.value == 3)
    #expect(result.standardError.contains("powervpn run: quarantine_cleared"))
    #expect(events.sleeps == [3_000, 3_000])
  }

  @Test func runNamesTheFailedAssessmentDimensionsWhenColdBaselineStaysRejected() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter, recoveryPasses: false,
        rejection: ProductCleanupRecoveryReport(
          failure: .coldBaselineRejected, source: .nativePortal,
          assessment: driftedColdBaselineAssessment(), attempts: 2, preflightSafe: true,
          mutationLeaseAcquired: true))
    )

    #expect(counter.value == 4)
    #expect(result.exitCode == 77)
    #expect(
      result.standardError.contains(
        "did not pass (dnsStable, persistentRoutesStable, structuralRoutesStable) after 4 attempts")
    )
    // Passing dimensions, the aggregate flag, the constant flags and the zero residue counts are
    // not failures.
    for passing in ["interfaceInventoryStable", "passed", "contains", "ResidueCount", "true"] {
      #expect(!result.standardError.contains(passing))
    }
    #expect(result.standardError.hasSuffix("next: powervpn recovery inspect --json\n"))
    #expect(ssh.starts == 0)
  }

  @Test func runRetriesTransientVendorHelperPreflightOnceTheHelperSettles() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter, events: events,
        quiescence: RunScriptedQuiescence([false, false, true]),
        rejection: preflightRejection(helperVisible: true),
        rejectionsBeforePass: 1)
    )

    #expect(result.exitCode == 0)
    #expect(counter.value == 2)
    #expect(
      events.all == [
        "recovery", "quiescent", "sleep:1000", "quiescent", "sleep:1000", "quiescent", "recovery",
      ])
  }

  @Test func runGivesUpWhenTheVendorHelperNeverSettles() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter, events: events,
        quiescence: RunScriptedQuiescence([false]), recoveryPasses: false,
        rejection: preflightRejection(helperVisible: true))
    )

    #expect(counter.value == 1)
    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("local preflight failed (vendor_helper_running"))
    #expect(events.sleeps.reduce(0, +) == 19_000)
    #expect(ssh.starts == 0)
  }

  @Test func runDoesNotRetryPreflightRejectionsThatNeedAHuman() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let ssh = RunScriptedSSH(execExitCode: 0)
    let counter = RecoveryInvocationCounter()
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, counter: counter, events: events, recoveryPasses: false,
        rejection: preflightRejection(helperVisible: true, guiRunning: true))
    )

    #expect(counter.value == 1)
    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("vendor_gui_running"))
    #expect(events.all == ["recovery"])
  }

  @Test func runSettlesBeforeMeasuredRecoveryWhenStartLeavesAQuarantine() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0)
    // A session whose master is gone: `up` quarantines it and exits 74.
    try store.save(activeState(controlPath: ssh.socket))
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, events: events,
        quiescence: RunScriptedQuiescence([false, false, true]))
    )

    #expect(result.exitCode == 0)
    #expect(
      events.all == [
        "quiescent", "sleep:1000", "quiescent", "sleep:1000", "quiescent", "recovery",
      ])
    #expect(result.standardError.contains("powervpn run: quarantine_cleared"))
    #expect(ssh.starts == 1)
  }

  @Test func runRetriesTransientLocalSafetyFailureThenStarts() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startFailure: "local_safety_check_failed", failingStarts: 1,
      store: store)
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store, events: events)
    )

    #expect(result.exitCode == 0)
    #expect(ssh.starts == 2)
    #expect(ssh.execs.count == 1)
    #expect(events.sleeps == [3_000])
  }

  @Test func runGivesUpOnPersistentLocalSafetyFailureAfterBoundedBackoff() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startFailure: "local_safety_check_failed", store: store)
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store, events: events)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 3)
    #expect(events.sleeps == [3_000, 6_000])
    #expect(result.standardError.contains("powervpn run: local_safety_check_failed"))
    #expect(result.standardError.hasSuffix("next: powervpn doctor --json\n"))
    #expect(ssh.execs.isEmpty)
  }

  @Test func runDoesNotRetryLocalSafetyFailureWhileTheVendorLogIsUnsafe() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startFailure: "local_safety_check_failed", store: store)
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, events: events, vendorLog: .absent)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(events.all.isEmpty)
    #expect(result.standardError.hasSuffix("next: powervpn doctor --json\n"))
  }

  @Test func runStopsRetryingLocalSafetyFailureWhenTheVendorNeverSettles() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startFailure: "local_safety_check_failed", store: store)
    let events = RunEventLog()

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(
        ssh: ssh, store: store, events: events, quiescence: RunScriptedQuiescence([false]))
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(events.sleeps.reduce(0, +) == 3_000 + 19_000)
  }

  @Test func runRefusesWhileAnotherTargetIsConnected() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0)
    let other = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".ssh/powervpn-run-other-\(UUID().uuidString).sock").path
    try store.save(
      UserProductSessionState(
        sessionID: UUID().uuidString.lowercased(), target: "thu52", controlPath: other,
        phase: .connected, ownerPID: 4321))
    ssh.markAlive(other)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("powervpn run: connected_to_other_target"))
    #expect(result.standardError.hasSuffix("next: powervpn down\n"))
    #expect(ssh.execs.isEmpty)
  }

  @Test func runRetriesOneTransientStartFailureThenReportsRetryable() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0, startFailure: "connection_failed", store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 75)
    #expect(ssh.starts == 2)
    #expect(result.standardError.contains("powervpn run: session_start_failed"))
    #expect(result.standardError.contains("next: powervpn run thu21 -- <same command>"))
    #expect(ssh.execs.isEmpty)
  }

  @Test func runTreatsCredentialFailureAsNeedingHuman() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0, startFailure: "runtime_unavailable", store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(result.standardError.contains("powervpn run: runtime_unavailable"))
    #expect(result.standardError.hasSuffix("next: powervpn doctor --json\n"))
  }

  @Test func runReportsLostSessionInsteadOfPassingSSH255() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 255, execKillsMaster: true)
    try store.save(activeState(controlPath: ssh.socket))
    ssh.markAlive(ssh.socket)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 75)
    #expect(result.standardError.contains("powervpn run: session_lost"))
  }

  @Test func runRejectsCommandWithoutSeparator() async throws {
    await #expect(throws: UserProductCommandError.self) {
      _ = try await runCurrentMachineUserProductCommand(
        ["run", "thu21", "hostname"],
        dependencies: runDependencies(ssh: RunScriptedSSH(execExitCode: 0))
      )
    }
  }

  @Test(arguments: [UserProductSSHRejection.authRejected, .hostKeyRejected])
  func runStopsForHumanWhenSSHRefusesTheMaster(_ rejection: UserProductSSHRejection)
    async throws
  {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0, startDiagnostics: sshDiagnostics(rejection))

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(ssh.execs.isEmpty)
    #expect(result.standardError.contains("powervpn run: \(rejection.rawValue)\n"))
    switch rejection {
    case .authRejected:
      #expect(result.standardError.contains("把 SSH 公钥装到服务器上"))
    case .hostKeyRejected:
      #expect(
        result.standardError.contains("ssh-keygen -f /Users/test/.ssh/known_hosts -R 192.0.2.21"))
      #expect(result.standardError.contains("powervpn ssh thu21 -- true"))
    }
    // ssh's own messages name the user and host: classified, never printed or kept.
    #expect(!result.standardError.contains("synthetic-user@"))
    #expect(!result.standardError.contains("verification failed"))
    #expect(ssh.diagnosticLogs.count == 1)
    #expect(ssh.diagnosticLogs.allSatisfy { !FileManager.default.fileExists(atPath: $0) })
  }

  @Test func upReportsAnSSHRefusalAsNeedingAHumanAndKeepsTheCleanupMarker() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0, startDiagnostics: sshDiagnostics(.authRejected))

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(result.sshRejection == .authRejected)
    #expect(result.standardError.hasPrefix("PowerVPN: thu21 rejected SSH public-key login"))
    #expect(result.standardError.contains("\nnext: install your SSH public key on the server"))
    #expect(try store.load()?.failure == "ssh_master_start_cleanup_unverified")
  }

  @Test func runReportsAnSSHRefusalEvenWhenTheProxyFinishedFirst() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startFailure: "connection_failed",
      startDiagnostics: sshDiagnostics(.authRejected), store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(result.standardError.contains("powervpn run: ssh_auth_rejected"))
  }

  @Test func runReportsAnSSHRefusalOverTheProxyCancellationSSHCaused() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    // ssh sends SIGHUP to its ProxyCommand when the login fails; the proxy may record that as a
    // verified-cleanup cancellation before `up` reads the state.
    let ssh = RunScriptedSSH(
      execExitCode: 0, startFailure: "cancelled",
      startDiagnostics: sshDiagnostics(.hostKeyRejected), store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(result.standardError.contains("powervpn run: ssh_host_key_rejected"))
  }

  @Test func upRemovesDiagnosticLogsAKilledStartLeftBehind() async throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let leftover = directory.appendingPathComponent("ssh-master-Ab12Cd.log").path
    #expect(FileManager.default.createFile(atPath: leftover, contents: Data("canary".utf8)))
    let unrelated = directory.appendingPathComponent("ssh-master-notes.txt").path
    #expect(FileManager.default.createFile(atPath: unrelated, contents: Data()))

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"],
      dependencies: runDependencies(ssh: RunScriptedSSH(execExitCode: 0), store: store)
    )

    #expect(result.exitCode == 0)
    #expect(!FileManager.default.fileExists(atPath: leftover))
    #expect(FileManager.default.fileExists(atPath: unrelated))
  }

  @Test func runStillRetriesSSHFailuresThatAreNotARefusal() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0,
      startDiagnostics:
        "kex_exchange_identification: Connection closed by remote host\r\nConnection closed by UNKNOWN port 65535\r\n"
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 75)
    #expect(ssh.starts == 2)
    #expect(result.standardError.hasPrefix("PowerVPN: SSH master did not start."))
    #expect(result.standardError.contains("powervpn run: session_start_failed"))
    #expect(ssh.diagnosticLogs.count == 2)
    #expect(ssh.diagnosticLogs.allSatisfy { !FileManager.default.fileExists(atPath: $0) })
  }

  @Test func masterStartRemovesItsDiagnosticLogOnSuccess() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 0)
    #expect(ssh.diagnosticLogs.count == 1)
    #expect(ssh.diagnosticLogs.allSatisfy { $0.hasPrefix(directory.path + "/ssh-master-") })
    #expect(ssh.diagnosticLogs.allSatisfy { !FileManager.default.fileExists(atPath: $0) })
  }

  @Test func diagnosticLogIsPrivateBoundedAndClassified() throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let log = try #require(UserProductSSHDiagnosticLog.create(directory: directory.path))
    defer { log.remove() }
    #expect(URL(fileURLWithPath: log.path).lastPathComponent.hasPrefix("ssh-master-"))
    var metadata = stat()
    #expect(lstat(log.path, &metadata) == 0)
    #expect(metadata.st_mode & S_IFMT == S_IFREG)
    #expect(metadata.st_mode & 0o777 == 0o600)
    #expect(log.failureClass() == nil)

    try Data(sshDiagnostics(.hostKeyRejected).utf8).write(to: URL(fileURLWithPath: log.path))
    #expect(log.failureClass() == .hostKeyRejected)

    let flood = String(repeating: "x", count: UserProductSSHDiagnosticLog.limitBytes)
    try Data((flood + sshDiagnostics(.authRejected)).utf8).write(
      to: URL(fileURLWithPath: log.path))
    #expect(log.failureClass() == nil)
  }

  @Test func diagnosticLogRemovalAlsoEmptiesTheFileAStartedMasterKeepsOpen() throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let log = try #require(UserProductSSHDiagnosticLog.create(directory: directory.path))
    let master = try #require(FileHandle(forWritingAtPath: log.path))
    defer { try? master.close() }
    master.write(Data(sshDiagnostics(.authRejected).utf8))

    log.remove()

    #expect(!FileManager.default.fileExists(atPath: log.path))
    var metadata = stat()
    #expect(fstat(master.fileDescriptor, &metadata) == 0)
    #expect(metadata.st_size == 0)
  }

  @Test func masterStartLogsOnlyErrorsToTheDiagnosticLog() {
    let arguments = UserProductSSHArguments.startMaster(
      target: "thu21", controlPath: "/Users/test/.ssh/cm", executablePath: "/x/powervpn",
      sessionID: "s", diagnosticLog: "/state/ssh-master-a.log")
    #expect(
      Array(arguments.prefix(4)) == ["-E", "/state/ssh-master-a.log", "-o", "LogLevel=ERROR"])
    let discarded = UserProductSSHArguments.startMaster(
      target: "thu21", controlPath: "/Users/test/.ssh/cm", executablePath: "/x/powervpn",
      sessionID: "s")
    #expect(!discarded.contains("-E") && !discarded.contains("LogLevel=ERROR"))
  }

  @Test func hostKeyRefusalNamesTheKnownHostsFileAndAliasSSHUses() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startDiagnostics: sshDiagnostics(.hostKeyRejected),
      configurationExtra:
        "userknownhostsfile /Users/test/.ssh/campus_hosts /Users/test/.ssh/k2\nhostkeyalias lab-alias\n"
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(result.sshRejection == .hostKeyRejected)
    #expect(
      result.standardError.contains("ssh-keygen -f /Users/test/.ssh/campus_hosts -R lab-alias"))
  }

  @Test(arguments: [ExistingSessionCase.active, .quarantined])
  func upRemovesLeftoverDiagnosticLogsBeforeAnyEarlyReturn(_ existing: ExistingSessionCase)
    async throws
  {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0)
    switch existing {
    case .active:
      try store.save(activeState(controlPath: ssh.socket))
      ssh.markAlive(ssh.socket)
    case .quarantined:
      try store.save(quarantinedRecoveryState())
    }
    let leftover = directory.appendingPathComponent("ssh-master-Ab12Cd.log").path
    #expect(FileManager.default.createFile(atPath: leftover, contents: Data("canary".utf8)))

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == (existing == .active ? 0 : 74))
    #expect(ssh.starts == 0)
    #expect(!FileManager.default.fileExists(atPath: leftover))
  }

  @Test(arguments: ProxyReceiptCase.all)
  func upKeepsTheProxyReceiptAndRanksItAgainstAnSSHRefusal(_ receiptCase: ProxyReceiptCase)
    async throws
  {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startDiagnostics: receiptCase.diagnostics,
      startPublishes: receiptCase.publish, store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == receiptCase.exitCode)
    let saved = try #require(try store.load())
    var published = saved
    receiptCase.publish(&published)
    #expect(saved == published, "up must not rewrite a receipt the proxy already published")
    #expect(saved.failure != "ssh_master_start_cleanup_unverified")
  }

  @Test func masterStartKeepsSSHQuietWhateverTheConfigAsksFor() throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let configuration = directory.appendingPathComponent("ssh_config").path
    try Data(
      "Host verbose-target\n  HostName 192.0.2.9\n  LogLevel DEBUG3\n  LogVerbose *\n".utf8
    ).write(to: URL(fileURLWithPath: configuration))
    let log = try #require(UserProductSSHDiagnosticLog.create(directory: directory.path))
    defer { log.remove() }

    // Real /usr/bin/ssh, no network: the ProxyCommand is /usr/bin/false, so ssh fails at once.
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
    process.arguments =
      ["-F", configuration]
      + UserProductSSHArguments.startMaster(
        target: "verbose-target", controlPath: directory.appendingPathComponent("cm").path,
        executablePath: "/usr/bin/false", sessionID: UUID().uuidString.lowercased(),
        diagnosticLog: log.path)
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()

    #expect(process.terminationStatus == 255)
    let written = try Data(contentsOf: URL(fileURLWithPath: log.path))
    #expect(!String(decoding: written, as: UTF8.self).contains("debug"))
    #expect(written.count < 1_024)
  }

  @Test func productFailuresEndWithNextAction() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())

    let result = try await runCurrentMachineUserProductCommand(
      ["up", "thu21"],
      dependencies: runDependencies(ssh: RunScriptedSSH(execExitCode: 0), store: store)
    )

    #expect(result.exitCode == 74)
    #expect(result.standardError.hasSuffix("next: powervpn recovery inspect --json\n"))
    #expect(
      userProductNextAction(in: "Check keys and run `powervpn doctor --json`.")
        == "powervpn doctor --json")
    #expect(userProductNextAction(in: "Close it before `powervpn up`.") == nil)
  }
}

/// Scripted `/usr/bin/ssh`: `-G` prints a valid Host block, `-O check` reports sockets marked
/// alive, `-f` starts a master (or records a proxy-side failure, or writes `startDiagnostics` to
/// its `-E` file and exits 255), anything else is the command.
private final class RunScriptedSSH: UserProductProcessRunning, @unchecked Sendable {
  let socket = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".ssh/powervpn-run-\(UUID().uuidString).sock").path
  private let lock = NSLock()
  private let execExitCode: Int32
  private let execKillsMaster: Bool
  private let startFailure: String?
  private let failingStarts: Int?
  private let startDiagnostics: String?
  private let startPublishes: (@Sendable (inout UserProductSessionState) -> Void)?
  private let configurationExtra: String
  private let store: UserProductSessionStateStore?
  private var alive: Set<String> = []
  private var startCount = 0
  private var execArguments: [[String]] = []
  private var diagnosticLogPaths: [String] = []

  init(
    execExitCode: Int32,
    execKillsMaster: Bool = false,
    startFailure: String? = nil,
    failingStarts: Int? = nil,
    startDiagnostics: String? = nil,
    startPublishes: (@Sendable (inout UserProductSessionState) -> Void)? = nil,
    configurationExtra: String = "",
    store: UserProductSessionStateStore? = nil
  ) {
    self.execExitCode = execExitCode
    self.execKillsMaster = execKillsMaster
    self.startFailure = startFailure
    self.failingStarts = failingStarts
    self.startDiagnostics = startDiagnostics
    self.startPublishes = startPublishes
    self.configurationExtra = configurationExtra
    self.store = store
  }

  func markAlive(_ path: String) { lock.withLock { _ = alive.insert(path) } }
  var starts: Int { lock.withLock { startCount } }
  var execs: [[String]] { lock.withLock { execArguments } }
  /// The `-E` file of every master start, in order.
  var diagnosticLogs: [String] { lock.withLock { diagnosticLogPaths } }

  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    if arguments.first == "-G" {
      return .init(
        started: true, exitCode: 0,
        output:
          "host thu21\nuser synthetic-user\nhostname 192.0.2.21\nport 22\ncontrolmaster auto\ncontrolpath \(socket)\n"
          + "userknownhostsfile /Users/test/.ssh/known_hosts /Users/test/.ssh/known_hosts2\n"
          + configurationExtra
      )
    }
    if arguments.contains("check"), let index = arguments.firstIndex(of: "-S") {
      let path = arguments[index + 1]
      let running = lock.withLock { alive.contains(path) }
      return .init(
        started: true, exitCode: running ? 0 : 255,
        output: running ? "Master running (pid=4321)\n" : "")
    }
    if arguments.contains("-f"), let index = arguments.firstIndex(of: "-S") {
      let attempt = lock.withLock { () -> Int in
        startCount += 1
        return startCount
      }
      if let log = arguments.firstIndex(of: "-E").map({ arguments[$0 + 1] }) {
        lock.withLock { diagnosticLogPaths.append(log) }
        if let startDiagnostics, let handle = FileHandle(forWritingAtPath: log) {
          handle.seekToEndOfFile()
          handle.write(Data(startDiagnostics.utf8))
          handle.closeFile()
        }
      }
      if let startFailure, let store, attempt <= (failingStarts ?? .max),
        let state = try? store.load()
      {
        _ = try? store.update(sessionID: state.sessionID) {
          $0.phase = .failed
          $0.cleanupVerified = true
          $0.failure = startFailure
        }
        return .init(started: true, exitCode: 255, output: "")
      }
      if let startPublishes, let store, let state = try? store.load() {
        // The proxy's own receipt, published before ssh exits.
        _ = try? store.update(sessionID: state.sessionID, startPublishes)
        return .init(started: true, exitCode: 255, output: "")
      }
      if startDiagnostics != nil { return .init(started: true, exitCode: 255, output: "") }
      markAlive(arguments[index + 1])
      return .init(started: true, exitCode: 0, output: "")
    }
    lock.withLock {
      execArguments.append(arguments)
      if execKillsMaster { alive.removeAll() }
    }
    return .init(started: true, exitCode: execExitCode, output: "")
  }
}

private func activeState(controlPath: String) -> UserProductSessionState {
  UserProductSessionState(
    sessionID: UUID().uuidString.lowercased(), target: "thu21", controlPath: controlPath,
    phase: .connected, ownerPID: 4321)
}

private func runDependencies(
  ssh: RunScriptedSSH,
  store: UserProductSessionStateStore = UserProductSessionStateStore(
    directory: recoveryTemporaryDirectory()),
  counter: RecoveryInvocationCounter = RecoveryInvocationCounter(),
  events: RunEventLog = RunEventLog(),
  quiescence: RunScriptedQuiescence = RunScriptedQuiescence([true]),
  vendorLog: VendorLogFinding = .bounded,
  recoveryPasses: Bool = true,
  rejection: ProductCleanupRecoveryReport = ProductCleanupRecoveryReport(
    failure: .coldBaselineRejected, source: .nativePortal, mutationLeaseAcquired: true),
  rejectionsBeforePass: Int? = nil
) -> UserProductCommandDependencies {
  UserProductCommandDependencies(
    loadConfiguration: recoveryConfiguration,
    processRunner: ssh,
    stateStore: store,
    executablePath: "/Users/test/.local/bin/powervpn",
    mutationLeaseAvailable: { true },
    systemStatus: recoverySystemStatus,
    proxyRunner: { _ in ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0) },
    recoveryRunner: { request, _, commit in
      counter.increment()
      events.record("recovery")
      if let rejectionsBeforePass {
        guard counter.value > rejectionsBeforePass else { return rejection }
      } else {
        guard recoveryPasses else { return rejection }
      }
      return await syntheticRecoveryMeasurement(request: request, commit: commit)
    },
    credentialFileSafe: { true },
    helperArtifactSafe: { true },
    vendorLogFinding: { vendorLog },
    vendorQuiescent: {
      events.record("quiescent")
      return quiescence.next()
    },
    signalMonitorFactory: { RecoveryNoopSignalMonitor() },
    sleepMilliseconds: { events.record("sleep:\($0)") },
    cleanupPollLimit: 1
  )
}

/// Orders the settle polls, sleeps and recovery attempts `run` performs.
private final class RunEventLog: @unchecked Sendable {
  private let lock = NSLock()
  private var recorded: [String] = []

  func record(_ event: String) { lock.withLock { recorded.append(event) } }
  var all: [String] { lock.withLock { recorded } }
  var sleeps: [Int] {
    all.compactMap { $0.hasPrefix("sleep:") ? Int($0.dropFirst("sleep:".count)) : nil }
  }
}

/// Answers each `vendorQuiescent` poll from the script, then repeats the last answer.
private final class RunScriptedQuiescence: @unchecked Sendable {
  private let lock = NSLock()
  private var answers: [Bool]

  init(_ answers: [Bool]) { self.answers = answers }

  func next() -> Bool {
    lock.withLock { answers.count > 1 ? answers.removeFirst() : (answers.first ?? true) }
  }
}

/// A rejected preflight whose findings are the vendor helper still being visible, optionally with
/// the vendor GUI running too (which only a human can fix).
private func preflightRejection(
  helperVisible: Bool,
  guiRunning: Bool = false
) -> ProductCleanupRecoveryReport {
  ProductCleanupRecoveryReport(
    failure: .preflightRejected,
    source: .nativePortal,
    preflight: VendorXPCPreflightEvidence(
      guiProcessAbsent: !guiRunning,
      helperProcessAbsent: !helperVisible,
      otherVendorHelperProcessesAbsent: true,
      helperLaunchdInactive: true,
      dnsRecoveryFileAbsent: true,
      vendorLogRotationSafe: true
    ),
    mutationLeaseAcquired: true
  )
}

/// Two otherwise cold snapshots whose DNS and structural routes differ, like two back-to-back
/// captures while Surge's TUN clones host routes.
private func driftedColdBaselineAssessment() -> NetworkColdRecoveryAssessment {
  let first = m2CaptureSnapshotFixture(effectiveSelectedRoute: .observed(selectedRouteToken: nil))
  let changed = NetworkCleanupFingerprint.observed(
    count: 1, sha256: String(repeating: "b", count: 64))
  let second = NetworkCleanupSnapshot(
    defaultRoute: first.defaultRoute,
    dns: changed,
    interfaces: first.interfaces,
    ipv4Routes: NetworkCleanupRouteSnapshot(
      // Drift a configuration route: cloned/expiring rows alone no longer fail the gate.
      structural: changed,
      persistent: changed,
      selectedRouteMatchCount: 0,
      selectedRouteTokens: [],
      effectiveSelectedRoute: first.ipv4Routes.effectiveSelectedRoute
    ),
    ipv6Routes: first.ipv6Routes,
    surge: first.surge,
    vendorProcesses: first.vendorProcesses,
    helperGeneration: first.helperGeneration,
    helperObservationState: first.helperObservationState
  )
  return NetworkColdRecoveryAssessment(first: first, second: second)
}

enum ExistingSessionCase: Sendable {
  case active
  case quarantined
}

/// A receipt `internal-session-proxy` publishes when ssh stops it, written with the same fields
/// it writes, already in place when `up` sees ssh exit.
struct ProxyReceiptCase: Sendable, CustomTestStringConvertible {
  let testDescription: String
  let phase: UserProductSessionPhase
  let cleanupVerified: Bool?
  let receiptVerified: Bool?
  let failure: String?
  let diagnostics: String
  let exitCode: Int32

  @Sendable func publish(_ state: inout UserProductSessionState) {
    state.phase = phase
    state.schemaVersion = 2
    state.cleanupVerified = cleanupVerified
    state.originalCleanupReceipt = receiptVerified.map(vendorCleanupReceipt(verified:))
    state.failure = failure
  }

  static let all: [Self] = [
    Self(
      testDescription: "normal stream close, verified receipt, refused login",
      phase: .disconnected, cleanupVerified: true, receiptVerified: true, failure: nil,
      diagnostics: sshDiagnostics(.authRejected), exitCode: 77),
    Self(
      testDescription: "failed proxy, verified receipt, refused host key",
      phase: .failed, cleanupVerified: true, receiptVerified: true,
      failure: "connection_failed", diagnostics: sshDiagnostics(.hostKeyRejected), exitCode: 77),
    Self(
      testDescription: "normal stream close, verified receipt, no refusal",
      phase: .disconnected, cleanupVerified: true, receiptVerified: true, failure: nil,
      diagnostics: "Connection closed by UNKNOWN port 65535\r\n", exitCode: 69),
    Self(
      testDescription: "unverified receipt outranks a refused login",
      phase: .failed, cleanupVerified: false, receiptVerified: false,
      failure: "cleanup_unproven", diagnostics: sshDiagnostics(.authRejected), exitCode: 74),
    Self(
      testDescription: "cleanup never recorded outranks a refused login",
      phase: .failed, cleanupVerified: nil, receiptVerified: nil,
      failure: "connection_failed", diagnostics: sshDiagnostics(.authRejected), exitCode: 74),
  ]
}

/// What OpenSSH 10 writes to its `-E` file for each refusal, user and host included.
func sshDiagnostics(_ rejection: UserProductSSHRejection) -> String {
  switch rejection {
  case .authRejected:
    "synthetic-user@192.0.2.21: Permission denied (publickey,password).\r\n"
  case .hostKeyRejected:
    "No ED25519 host key is known for 192.0.2.21 and you have requested strict checking.\r\n"
      + "Host key verification failed.\r\n"
  }
}

private func vendorCleanupReceipt(verified: Bool) -> UserProductOriginalCleanupReceipt {
  UserProductOriginalCleanupReceipt(
    ProductPersistentTunnelShutdownReport(
      state: .stopped,
      cleanupPath: verified ? .sameLeaseStop : .cleanupUnproven,
      stopOutcome: verified ? .transportAcknowledged : .notAttempted,
      emergencyStopOutcome: .notAttempted,
      authorizationClose: .accepted,
      authorizationOwnedMaterialErased: true,
      cleanupEvidence: ProductM2CleanupEvidence(
        defaultRouteRestored: true,
        dnsRestored: verified,
        interfacesRestored: true,
        utunRestored: true,
        persistentRoutesRestored: true,
        selectedRouteResidueCount: 0,
        surgeStateRestored: true,
        vendorProcessesRestored: true,
        helperGenerationRestored: true,
        structuralRouteTablesEqual: true
      ),
      cleanupVerified: verified,
      cleanupCaptureState: .measuredComplete,
      cleanupCaptureAttemptCount: 1
    ))
}
