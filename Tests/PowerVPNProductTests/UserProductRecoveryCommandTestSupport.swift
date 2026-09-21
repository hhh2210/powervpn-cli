import Foundation

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

func recoveryDependencies(
  store: UserProductSessionStateStore,
  counter: RecoveryInvocationCounter = RecoveryInvocationCounter(),
  masterExitCode: Int32 = 255
) -> UserProductCommandDependencies {
  UserProductCommandDependencies(
    loadConfiguration: recoveryConfiguration,
    processRunner: RecoveryCommandProcessRunner(exitCode: masterExitCode),
    stateStore: store,
    executablePath: "/Users/test/.local/bin/powervpn",
    mutationLeaseAvailable: { true },
    systemStatus: recoverySystemStatus,
    proxyRunner: { _ in
      ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
    },
    recoveryRunner: { request, _, commit in
      counter.increment()
      return await syntheticRecoveryMeasurement(request: request, commit: commit)
    },
    credentialFileSafe: { true },
    helperArtifactSafe: { true },
    vendorLogSafe: { true },
    signalMonitorFactory: { RecoveryNoopSignalMonitor() },
    cleanupPollLimit: 1
  )
}

func syntheticRecoveryMeasurement(
  request: ProductCleanupRecoveryRequest,
  commit: ProductCleanupRecoveryRuntime.CommitRecovered
) async -> ProductCleanupRecoveryReport {
  let fixture = try! authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
  let state = AuthorizationLeaseTestState()
  let lease = testAuthorizationLease(snapshot: fixture.snapshot, state: state)
  let attempt = productM2AuthorizationAttempt(lease, trace: ProductM2TestTrace())
  let snapshot = m2CaptureSnapshotFixture(
    effectiveSelectedRoute: .observed(selectedRouteToken: nil))
  let runtime = ProductCleanupRecoveryRuntime(
    dependencies: ProductCleanupRecoveryDependencies(
      acquireMutationLease: { RecoveryCommandMutationLease() },
      beginAuthorization: { _ in attempt },
      observeGeneration: { _ in m2ColdGeneration },
      captureNetwork: { _, _, _ in snapshot },
      checkPreflight: { _, _ in recoverySafePreflight }
    ))
  return await runtime.run(request, commitRecovered: commit)
}

let recoverySafePreflight = VendorXPCPreflightEvidence(
  guiProcessAbsent: true,
  helperProcessAbsent: true,
  otherVendorHelperProcessesAbsent: true,
  helperLaunchdInactive: true,
  dnsRecoveryFileAbsent: true,
  vendorLogRotationSafe: true
)

final class RecoveryCommandMutationLease: ProductMutationLeaseHolding,
  @unchecked Sendable
{}

final class RecoveryNoopSignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  func start(handler: @escaping @Sendable () -> Void) {}
  func stop() {}
}

final class RecoverySignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?

  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock { self.handler = handler }
  }
  func stop() { lock.withLock { handler = nil } }
  func trigger() { lock.withLock { handler }?() }
}

final class RecoveryCancellationGate: @unchecked Sendable {
  private let condition = NSCondition()
  private var started = false

  func waitForCancellation() {
    condition.lock()
    started = true
    condition.broadcast()
    condition.unlock()
    while !Task.isCancelled { usleep(10_000) }
  }

  func waitUntilStarted() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date().addingTimeInterval(1)
    while !started {
      guard condition.wait(until: deadline) else { return started }
    }
    return true
  }
}

final class RecoveryCommandProcessRunner: UserProductProcessRunning,
  @unchecked Sendable
{
  private let exitCode: Int32
  init(exitCode: Int32) { self.exitCode = exitCode }
  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    .init(started: true, exitCode: exitCode, output: "")
  }
}

final class RecoveryUpProcessRunner: UserProductProcessRunning,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var checkCount = 0

  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    if arguments.first == "-G" {
      let socket = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".ssh/powervpn-recovery-up.sock").path
      return .init(
        started: true,
        exitCode: 0,
        output:
          "host thu21\nuser synthetic-user\nhostname 192.0.2.21\nport 22\ncontrolmaster auto\ncontrolpath \(socket)\n"
      )
    }
    if arguments.contains("check") {
      let invocation = lock.withLock { () -> Int in
        defer { checkCount += 1 }
        return checkCount
      }
      return .init(
        started: true,
        exitCode: invocation < 2 ? 255 : 0,
        output: invocation < 2 ? "" : "Master running (pid=4321)\n"
      )
    }
    if arguments.contains("-f") { return .init(started: true, exitCode: 0, output: "") }
    return .init(started: false, exitCode: 70, output: "")
  }
}

final class RecoveryFailedUpProcessRunner: UserProductProcessRunning,
  @unchecked Sendable
{
  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    if arguments.first == "-G" {
      let socket = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".ssh/powervpn-recovery-failed-up.sock").path
      return .init(
        started: true, exitCode: 0,
        output:
          "host thu21\nuser synthetic-user\nhostname 192.0.2.21\nport 22\ncontrolmaster auto\ncontrolpath \(socket)\n"
      )
    }
    if arguments.contains("check") { return .init(started: true, exitCode: 255, output: "") }
    if arguments.contains("-f") { return .init(started: true, exitCode: 1, output: "") }
    return .init(started: false, exitCode: 70, output: "")
  }
}

final class RecoveryInvocationCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  func increment() { lock.withLock { count += 1 } }
  var value: Int { lock.withLock { count } }
}

final class RecoveryDirectorySyncScript: @unchecked Sendable {
  private let lock = NSLock()
  private var results: [Bool]

  init(_ results: [Bool]) { self.results = results }

  func call(_ path: String) -> Bool {
    lock.withLock {
      guard !results.isEmpty else { return true }
      return results.removeFirst()
    }
  }
}

func quarantinedRecoveryState() -> UserProductSessionState {
  UserProductSessionState(
    sessionID: UUID().uuidString.lowercased(),
    target: "thu21",
    controlPath: "/Users/test/.ssh/powervpn-recovery.sock",
    phase: .failed,
    ownerPID: 51_342,
    cleanupVerified: false,
    failure: "cleanup_unproven"
  )
}

func recoveryConfiguration() throws -> PowerVPNTargetsConfiguration {
  try PowerVPNTargetsConfiguration.decode(
    Data(
      """
      {"portalOrigin":"https://192.0.2.1:4443","targets":{"thu21":{"host":"192.0.2.21","user":"synthetic-user","resource":"Campus NC"}}}
      """.utf8
    ))
}

func recoverySystemStatus() -> PowerVPNStatus {
  PowerVPNStatus(
    appVersion: "3.2.1", appBuild: "24572", appArchitectures: ["x86_64"],
    appRunning: false,
    helper: HelperState(
      state: "not running", pid: nil, runs: 9, successiveCrashes: 9,
      lastTerminatingSignal: "Illegal instruction: 4"),
    tunnel: TunnelLogState(
      health: .stopped, latestEvent: "helper not running", historicalHint: false)
  )
}

func recoveryTemporaryDirectory() -> URL {
  FileManager.default.temporaryDirectory
    .appendingPathComponent("powervpn-recovery-command-tests-\(UUID().uuidString)")
}
