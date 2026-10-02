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
  private let store: UserProductSessionStateStore?
  private var alive: Set<String> = []
  private var startCount = 0
  private var execArguments: [[String]] = []

  init(
    execExitCode: Int32,
    execKillsMaster: Bool = false,
    startFailure: String? = nil,
    store: UserProductSessionStateStore? = nil
  ) {
    self.execExitCode = execExitCode
    self.execKillsMaster = execKillsMaster
    self.startFailure = startFailure
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
      lock.withLock { startCount += 1 }
      if let startFailure, let store, let state = try? store.load() {
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
  recoveryPasses: Bool = true
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
      guard recoveryPasses else {
        return ProductCleanupRecoveryReport(
          failure: .coldBaselineRejected, source: .nativePortal, mutationLeaseAcquired: true)
      }
      return await syntheticRecoveryMeasurement(request: request, commit: commit)
    },
    credentialFileSafe: { true },
    helperArtifactSafe: { true },
    vendorLogSafe: { true },
    signalMonitorFactory: { RecoveryNoopSignalMonitor() },
    sleepMilliseconds: { _ in },
    cleanupPollLimit: 1
  )
}
