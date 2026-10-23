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

  @Test(arguments: [UserProductSSHRejection.authRejected, .hostKeyRejected(staleEntry: nil)])
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
    #expect(result.standardError.contains("powervpn run: \(rejection.token)\n"))
    switch rejection {
    case .authRejected:
      #expect(result.standardError.contains("把 SSH 公钥装到服务器上"))
    case .hostKeyRejected:
      #expect(result.standardError.contains("next: run `powervpn ssh thu21 -- true`"))
      #expect(result.standardError.contains("`LogLevel QUIET` in ~/.ssh/config hides why"))
    }
    // ssh's own messages name the user and host: classified, never printed or kept.
    #expect(!result.standardError.contains("synthetic-user@"))
    #expect(!result.standardError.contains("verification failed"))
    #expect(ssh.diagnosticLogs == 1)
    #expect(ssh.masterLogsAreClosed)
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
      startDiagnostics: sshDiagnostics(.hostKeyRejected(staleEntry: nil)), store: store)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(result.standardError.contains("powervpn run: ssh_host_key_rejected"))
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
    #expect(ssh.diagnosticLogs == 2)
    #expect(ssh.masterLogsAreClosed)
  }

  @Test func masterStartClosesItsDiagnosticLogOnSuccess() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(execExitCode: 0)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 0)
    #expect(ssh.diagnosticLogs == 1)
    #expect(ssh.masterLogsAreClosed)
  }

  @Test func diagnosticPipeIsBoundedAndClassified() throws {
    let pipe = try #require(UserProductSSHDiagnosticPipe.create())
    // Only ssh gets the write end, as its standard output; no other child inherits it.
    #expect(fcntl(pipe.writer, F_GETFD) & FD_CLOEXEC != 0)
    #expect(pipe.rejection() == nil)
    try writeAsSSH(sshDiagnostics(.hostKeyRejected(staleEntry: nil)), to: pipe)
    #expect(pipe.rejection() == .hostKeyRejected(staleEntry: nil))
    pipe.close()

    // More than the limit, and more than a pipe buffers, is drained (ssh never blocks) but not
    // classified.
    let flooded = try #require(UserProductSSHDiagnosticPipe.create())
    defer { flooded.close() }
    let flood = String(repeating: "x", count: 8 * UserProductSSHDiagnosticPipe.limitBytes)
    #expect(writesWithinTwoSeconds(flood + sshDiagnostics(.authRejected), to: flooded))
    #expect(flooded.rejection() == nil)
    #expect(flooded.collectedByteCount == UserProductSSHDiagnosticPipe.limitBytes + 1)
  }

  @Test func messagesAStartedMasterLogsLaterGoNowhere() throws {
    let pipe = try #require(UserProductSSHDiagnosticPipe.create())
    // The master's log descriptor: its own copy of the standard output it started with.
    let master = dup(pipe.writer)
    try #require(master >= 0)
    defer { Darwin.close(master) }
    #expect(fcntl(master, F_SETNOSIGPIPE, 1) == 0)
    let early = Array("debug-free startup line\n".utf8)
    #expect(write(master, early, early.count) == early.count)

    pipe.close()

    // A RemoteForward failure an hour later: refused, nothing kept anywhere.
    let late = Array("connect_to missing.invalid port 80: failed.\n".utf8)
    #expect(write(master, late, late.count) == -1)
    #expect(errno == EPIPE)
  }

  @Test func realSSHKeepsRunningAfterItsDiagnosticPipeCloses() async throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let configuration = directory.appendingPathComponent("ssh_config").path
    try Data("Host slow-target\n  HostName 192.0.2.9\n".utf8)
      .write(to: URL(fileURLWithPath: configuration))
    let pipe = try #require(UserProductSSHDiagnosticPipe.create())

    // No network: the ProxyCommand sleeps, then closes, and ssh logs that after the pipe closed.
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
    process.arguments = [
      "-F", configuration, "-E", "/dev/fd/1", "-o", "LogLevel=DEBUG1", "-o", "BatchMode=yes",
      "-o", "ProxyCommand=/bin/sleep 1", "slow-target", "true",
    ]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle(fileDescriptor: pipe.writer, closeOnDealloc: false)
    process.standardError = FileHandle.nullDevice
    try process.run()
    // Process leaves the parent's end alone, so `close()` closes it once and nothing else.
    #expect(fcntl(pipe.writer, F_GETFD) != -1)
    for _ in 0..<500 where pipe.collectedByteCount == 0 {
      try await Task.sleep(for: .milliseconds(10))
    }
    #expect(pipe.collectedByteCount > 0, "ssh logged to its standard output")
    pipe.close()
    process.waitUntilExit()

    // Killed by SIGPIPE would be `.uncaughtSignal`; ssh ignores it and fails only on the proxy.
    #expect(process.terminationReason == .exit)
    #expect(process.terminationStatus == 255)
  }

  @Test func masterStartLogsOnlyErrorsToTheDiagnosticLog() {
    let arguments = UserProductSSHArguments.startMaster(
      target: "thu21", controlPath: "/Users/test/.ssh/cm", executablePath: "/x/powervpn",
      sessionID: "s", logsToStandardOutput: true)
    #expect(Array(arguments.prefix(4)) == ["-E", "/dev/fd/1", "-o", "LogLevel=ERROR"])
    let discarded = UserProductSSHArguments.startMaster(
      target: "thu21", controlPath: "/Users/test/.ssh/cm", executablePath: "/x/powervpn",
      sessionID: "s")
    #expect(!discarded.contains("-E") && !discarded.contains("LogLevel=ERROR"))
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

  /// Without the overrides the first config logs about 3 KB of debug lines, and the second nothing.
  @Test(arguments: ["LogLevel DEBUG3\n  LogVerbose *", "LogLevel QUIET"])
  func masterStartLogsJustErrorsWhateverTheConfigAsksFor(_ setting: String) throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let configuration = directory.appendingPathComponent("ssh_config").path
    try Data(
      "Host configured-target\n  HostName 192.0.2.9\n  \(setting)\n".utf8
    ).write(to: URL(fileURLWithPath: configuration))
    let pipe = try #require(UserProductSSHDiagnosticPipe.create())
    defer { pipe.close() }

    // Real /usr/bin/ssh through the runner `up` uses, no network: the ProxyCommand is an SSH-1
    // server, which ssh refuses with one ERROR line.
    let launch = FoundationUserProductProcessRunner().run(
      executable: "/usr/bin/ssh",
      arguments: ["-F", configuration]
        + UserProductSSHArguments.startMaster(
          target: "configured-target", controlPath: directory.appendingPathComponent("cm").path,
          executablePath: try sshOneServer(in: directory), sessionID: "s",
          logsToStandardOutput: true),
      io: .outputOnly(to: pipe.writer))

    #expect(launch.exitCode == 255)
    #expect(pipe.rejection() == nil)
    // The ERROR line arrived, so neither QUIET nor a rejected command-line option silenced it;
    // ERROR alone is at most a line or two.
    #expect(pipe.collectedByteCount > 0)
    #expect(pipe.collectedByteCount < 512)
  }

  @Test func sshDoesNotWaitForAnUpThatDiedBeforeItsLogOpened() throws {
    let directory = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let configuration = directory.appendingPathComponent("ssh_config").path
    try Data("Host old-target\n  HostName 192.0.2.9\n".utf8)
      .write(to: URL(fileURLWithPath: configuration))
    let pipe = try #require(UserProductSSHDiagnosticPipe.create())
    // `up` killed right after spawning ssh: of the pipe, only ssh's standard output is left.
    let standardOutput = dup(pipe.writer)
    try #require(standardOutput >= 0)
    defer { Darwin.close(standardOutput) }
    pipe.close()

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
    process.arguments =
      ["-F", configuration]
      + UserProductSSHArguments.startMaster(
        target: "old-target", controlPath: directory.appendingPathComponent("cm").path,
        executablePath: try sshOneServer(in: directory), sessionID: "s",
        logsToStandardOutput: true)
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle(fileDescriptor: standardOutput, closeOnDealloc: false)
    process.standardError = FileHandle.nullDevice
    try process.run()
    let deadline = Date().addingTimeInterval(10)
    while process.isRunning, Date() < deadline { usleep(10_000) }
    let blocked = process.isRunning
    if blocked {
      kill(process.processIdentifier, SIGKILL)
      process.waitUntilExit()
    }

    #expect(!blocked, "ssh waited for a reader that is gone")
    // It logged its ERROR line into the void (EPIPE, not SIGPIPE) and failed only on the server.
    #expect(process.terminationReason == .exit)
    #expect(process.terminationStatus == 255)
  }

  @Test func runNamesTheStaleKnownHostsLineSSHReported() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let keys = recoveryTemporaryDirectory().appendingPathComponent("My Keys 中文")
    try FileManager.default.createDirectory(at: keys, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: keys.deletingLastPathComponent()) }
    let knownHosts = keys.appendingPathComponent("known_hosts").path
    #expect(FileManager.default.createFile(atPath: knownHosts, contents: Data()))
    let store = UserProductSessionStateStore(directory: directory)
    let diagnostics = changedHostKeyDiagnostics(location: sshEscaped(knownHosts) + ":2")
    let ssh = RunScriptedSSH(execExitCode: 0, startDiagnostics: diagnostics)

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(ssh.starts == 1)
    #expect(
      result.standardError.hasPrefix(
        "PowerVPN: ssh does not trust the host key of thu21 (192.0.2.21): it differs from the one known_hosts recorded.\n"
      ))
    #expect(result.standardError.contains("powervpn run: ssh_host_key_rejected\n"))
    #expect(
      result.standardError.contains(
        "next: if the server really changed its host key, delete line 2 of `\(knownHosts)`,"))
    // Only the file and line are shown; the warning and the server's fingerprint are not.
    #expect(!result.standardError.contains("IDENTIFICATION"))
    #expect(!result.standardError.contains("SHA256:"))
  }

  @Test(arguments: [UnnamableStaleKey.knownHostsCommand, .newlineInPath])
  func runNamesNoLineToDeleteWhenSSHNamesNoFileOfItsOwn(_ stale: UnnamableStaleKey)
    async throws
  {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let files = recoveryTemporaryDirectory()
    try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: files) }
    // A real file, so only the newline after it gives the path away.
    let decoy = files.appendingPathComponent("known_hosts").path
    #expect(FileManager.default.createFile(atPath: decoy, contents: Data()))
    let location: String
    switch stale {
    case .knownHostsCommand:
      location = "KnownHostsCommand-192.0.2.21:1"
    case .newlineInPath:
      // UserKnownHostsFile `<decoy>:7<LF>archive/known_hosts`: ssh logs the LF as it is.
      location = decoy + ":7\narchive/known_hosts:2"
    }
    let store = UserProductSessionStateStore(directory: directory)
    let ssh = RunScriptedSSH(
      execExitCode: 0, startDiagnostics: changedHostKeyDiagnostics(location: location))

    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: runDependencies(ssh: ssh, store: store)
    )

    #expect(result.exitCode == 77)
    #expect(result.standardError.contains("powervpn run: ssh_host_key_rejected\n"))
    #expect(!result.standardError.contains("delete line"))
  }

  @Test func knownHostsEntryIsReadFromWhatSSHLogs() {
    func entry(bytes: [UInt8]) -> UserProductKnownHostsEntry? {
      UserProductKnownHostsEntry(sshMessages: Data(bytes))
    }
    func entry(_ text: String) -> UserProductKnownHostsEntry? { entry(bytes: Array(text.utf8)) }
    let path = "/Users/synthetic-user/My Keys 中文/known_hosts"
    let chinese = UserProductKnownHostsEntry(file: path, line: 2)

    // OpenSSH 10.5 in the C locale escapes every byte outside ASCII.
    let escaped = "/Users/synthetic-user/My Keys \\344\\270\\255\\346\\226\\207/known_hosts"
    #expect(sshEscaped(path) == escaped)
    #expect(entry(changedHostKeyDiagnostics(location: escaped + ":2")) == chinese)
    // In a UTF-8 locale it leaves some of them raw.
    var mixed: [UInt8] = Array("Offending ED25519 key in /Users/synthetic-user/My Keys ".utf8)
    mixed += [0xE4, 0xB8]
    mixed += Array("\\255".utf8)
    mixed += [0xE6]
    mixed += Array("\\226\\207/known_hosts:2\r\n".utf8)
    #expect(entry(bytes: mixed) == chinese)
    let backslash = UserProductKnownHostsEntry(file: "/tmp/a\\b:c/known_hosts", line: 17)
    #expect(entry("Offending RSA key in /tmp/a\\\\b:c/known_hosts:17\r\n") == backslash)
    // CheckHostIP's line is no refusal; a path that would drive the terminal is not shown, nor
    // one with a newline, which ssh does not escape.
    #expect(entry("Offending key for IP in /Users/me/.ssh/known_hosts:3\r\n") == nil)
    #expect(entry("Offending ED25519 key in /tmp/\\033[31m/known_hosts:1\r\n") == nil)
    #expect(entry("Offending ED25519 key in /tmp/known_hosts:7\narchive/known_hosts:2\r\n") == nil)
    #expect(entry(sshDiagnostics(.hostKeyRejected(staleEntry: nil))) == nil)
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
/// its `-E` log and exits 255), anything else is the command.
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
  private let store: UserProductSessionStateStore?
  private var alive: Set<String> = []
  private var startCount = 0
  private var execArguments: [[String]] = []
  /// Each master's own copy of its `-E` log, kept as a running master keeps it.
  private var masterLogs: [Int32] = []

  init(
    execExitCode: Int32,
    execKillsMaster: Bool = false,
    startFailure: String? = nil,
    failingStarts: Int? = nil,
    startDiagnostics: String? = nil,
    startPublishes: (@Sendable (inout UserProductSessionState) -> Void)? = nil,
    store: UserProductSessionStateStore? = nil
  ) {
    self.execExitCode = execExitCode
    self.execKillsMaster = execKillsMaster
    self.startFailure = startFailure
    self.failingStarts = failingStarts
    self.startDiagnostics = startDiagnostics
    self.startPublishes = startPublishes
    self.store = store
  }

  func markAlive(_ path: String) { lock.withLock { _ = alive.insert(path) } }
  var starts: Int { lock.withLock { startCount } }
  var execs: [[String]] { lock.withLock { execArguments } }
  /// How many master starts got their `-E` log as standard output.
  var diagnosticLogs: Int { lock.withLock { masterLogs.count } }
  /// Whether every master's log now refuses writes, as its later messages would find.
  var masterLogsAreClosed: Bool {
    lock.withLock { masterLogs.allSatisfy { write($0, "x", 1) == -1 && errno == EPIPE } }
  }

  deinit {
    for log in masterLogs { Darwin.close(log) }
  }

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
      if let index = arguments.firstIndex(of: "-E") {
        // Like real ssh, which closes every other inherited descriptor, it can only log to the
        // standard output it is given.
        guard arguments[index + 1] == "/dev/fd/1", case .outputOnly(let output) = io else {
          return .init(started: true, exitCode: 1, output: "")
        }
        let log = dup(output)
        if log >= 0, fcntl(log, F_SETNOSIGPIPE, 1) == 0 {
          lock.withLock { masterLogs.append(log) }
          if let startDiagnostics {
            let bytes = Array(startDiagnostics.utf8)
            _ = write(log, bytes, bytes.count)
          }
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
      failure: "connection_failed", diagnostics: sshDiagnostics(.hostKeyRejected(staleEntry: nil)),
      exitCode: 77),
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

/// What OpenSSH 10.5 logs when the host key changed and the stale one is at `location`
/// (`FILE:LINE`, as ssh writes it); the fingerprint is made up.
func changedHostKeyDiagnostics(location: String) -> String {
  let lines: [String] = [
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
    "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @",
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
    "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!",
    "Someone could be eavesdropping on you right now (man-in-the-middle attack)!",
    "It is also possible that a host key has just been changed.",
    "The fingerprint for the ED25519 key sent by the remote host is",
    "SHA256:Synthetic0Fingerprint0For0Tests0Only0000000.",
    "Please contact your system administrator.",
    "Add correct host key in /Users/synthetic-user/.ssh/known_hosts to get rid of this message.",
    "Offending ED25519 key in " + location,
    "Host key for 192.0.2.21 has changed and you have requested strict checking.",
    "Host key verification failed.",
  ]
  return lines.map { (line: String) -> String in line + "\r\n" }.joined()
}

/// `path` as OpenSSH 10.5 logs it in the C locale: each byte outside ASCII as `\ooo`, and a
/// backslash as `\\`.
func sshEscaped(_ path: String) -> String {
  var escaped = ""
  for byte in path.utf8 {
    if byte == UInt8(ascii: "\\") {
      escaped += "\\\\"
    } else if byte < 0x80 {
      escaped.unicodeScalars.append(UnicodeScalar(byte))
    } else {
      escaped += "\\" + String(byte, radix: 8)
    }
  }
  return escaped
}

enum UnnamableStaleKey: Sendable {
  case knownHostsCommand
  case newlineInPath
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

/// Writes `text` as ssh logs it: through its own copy of the write end.
private func writeAsSSH(_ text: String, to pipe: UserProductSSHDiagnosticPipe) throws {
  let log = dup(pipe.writer)
  try #require(log >= 0)
  defer { Darwin.close(log) }
  let bytes = Array(text.utf8)
  #expect(write(log, bytes, bytes.count) == bytes.count)
}

/// Writes `text` without blocking; false when the reader has not drained it within two seconds.
private func writesWithinTwoSeconds(_ text: String, to pipe: UserProductSSHDiagnosticPipe) -> Bool {
  let descriptor = dup(pipe.writer)
  guard descriptor >= 0 else { return false }
  defer { Darwin.close(descriptor) }
  guard fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else { return false }
  let bytes = Array(text.utf8)
  var offset = 0
  let deadline = Date().addingTimeInterval(2)
  while offset < bytes.count, Date() < deadline {
    let written = bytes[offset...].withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
    if written > 0 { offset += written } else { usleep(1_000) }
  }
  return offset == bytes.count
}

/// An executable that speaks as an SSH-1 server, for a ProxyCommand that needs no network: ssh
/// refuses it with one ERROR-level line and exits 255.
private func sshOneServer(in directory: URL) throws -> String {
  let path = directory.appendingPathComponent("ssh-one-server").path
  try Data("#!/bin/sh\necho SSH-1.5-test\n".utf8).write(to: URL(fileURLWithPath: path))
  #expect(chmod(path, 0o700) == 0)
  return path
}
