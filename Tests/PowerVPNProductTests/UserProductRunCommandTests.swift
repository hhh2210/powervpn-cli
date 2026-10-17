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
/// alive, `-f` starts a master (or records a proxy-side failure), anything else is the command.
private final class RunScriptedSSH: UserProductProcessRunning, @unchecked Sendable {
  let socket = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".ssh/powervpn-run-\(UUID().uuidString).sock").path
  private let lock = NSLock()
  private let execExitCode: Int32
  private let execKillsMaster: Bool
  private let startFailure: String?
  private let failingStarts: Int?
  private let store: UserProductSessionStateStore?
  private var alive: Set<String> = []
  private var startCount = 0
  private var execArguments: [[String]] = []

  init(
    execExitCode: Int32,
    execKillsMaster: Bool = false,
    startFailure: String? = nil,
    failingStarts: Int? = nil,
    store: UserProductSessionStateStore? = nil
  ) {
    self.execExitCode = execExitCode
    self.execKillsMaster = execKillsMaster
    self.startFailure = startFailure
    self.failingStarts = failingStarts
    self.store = store
  }

  func markAlive(_ path: String) { lock.withLock { _ = alive.insert(path) } }
  var starts: Int { lock.withLock { startCount } }
  var execs: [[String]] { lock.withLock { execArguments } }

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
