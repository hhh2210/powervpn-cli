import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct UserProductRepairCommandTests {
  @Test func boundedLogNeedsNoApproval() async throws {
    let harness = RepairHarness(findings: [.bounded])
    let result = try await harness.repair()

    #expect(result.exitCode == 0)
    #expect(try repairField(result, "outcome") as? String == "not_required")
    #expect(harness.runner.calls.isEmpty)
  }

  @Test func absentLogIsCreatedRootOnlyThroughOneNativeApproval() async throws {
    let harness = RepairHarness(findings: [.absent, .bounded])
    let result = try await harness.repair()

    #expect(result.exitCode == 0)
    #expect(try repairField(result, "outcome") as? String == "repaired")
    #expect(try repairField(result, "nextAction") as? String == "powervpn recovery clear --json")
    let call = try #require(harness.runner.calls.first)
    #expect(harness.runner.calls.count == 1)
    #expect(call.executable == "/usr/bin/osascript")
    let script = try #require(call.arguments.last)
    #expect(script.contains("set -C; umask 077; : > /var/log/vsgvpn.log"))
    #expect(script.contains("/usr/sbin/chown root:wheel /var/log/vsgvpn.log"))
    #expect(script.contains("/bin/chmod 0600 /var/log/vsgvpn.log"))
    #expect(script.contains("with administrator privileges"))
  }

  @Test func unsafePermissionsAreTightenedWithoutRecreatingTheLog() async throws {
    let harness = RepairHarness(findings: [.unsafePermissions, .bounded])
    let result = try await harness.repair()

    #expect(result.exitCode == 0)
    let script = try #require(harness.runner.calls.first?.arguments.last)
    #expect(!script.contains(": >"))
    #expect(script.contains("/bin/chmod 0600 /var/log/vsgvpn.log"))
  }

  @Test func busyVendorOrSessionNeverRequestsApproval() async throws {
    let busy = RepairHarness(findings: [.absent], quiescent: false)
    let busyResult = try await busy.repair()
    #expect(busyResult.exitCode == 75)
    #expect(try repairField(busyResult, "outcome") as? String == "vendor_busy")
    #expect(busy.runner.calls.isEmpty)

    let leased = RepairHarness(findings: [.absent], leaseAvailable: false)
    let leasedResult = try await leased.repair()
    #expect(leasedResult.exitCode == 75)
    #expect(leased.runner.calls.isEmpty)
  }

  @Test func dataLosingStatesAreLeftToTheUser() async throws {
    for finding in [VendorLogFinding.oversized, .unsupported, .unavailable] {
      let harness = RepairHarness(findings: [finding])
      let result = try await harness.repair()
      #expect(result.exitCode == 74)
      #expect(try repairField(result, "outcome") as? String == "not_repairable")
      #expect(harness.runner.calls.isEmpty)
    }
  }

  @Test func declinedApprovalStaysBlockedAndRepeatsTheRepairStep() async throws {
    let harness = RepairHarness(findings: [.absent, .absent], approvalExitCode: 1)
    let result = try await harness.repair()

    #expect(result.exitCode == 77)
    #expect(try repairField(result, "outcome") as? String == "approval_not_granted")
    #expect(try repairField(result, "nextAction") as? String == "powervpn repair vendor-log --json")
    #expect(!result.standardOutput.contains("vsgvpn"))
  }

  @Test func inspectPointsAtRepairWhenOnlyTheVendorLogFailed() async throws {
    let directory = recoveryTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    try store.save(quarantinedRecoveryState())
    let base = recoveryDependencies(store: store)
    let dependencies = UserProductCommandDependencies(
      loadConfiguration: base.loadConfiguration,
      processRunner: base.processRunner,
      stateStore: store,
      executablePath: base.executablePath,
      mutationLeaseAvailable: { true },
      systemStatus: base.systemStatus,
      proxyRunner: base.proxyRunner,
      recoveryRunner: { _, _, _ in
        ProductCleanupRecoveryReport(
          failure: .preflightRejected,
          source: .nativePortal,
          preflight: absentVendorLogPreflight,
          mutationLeaseAcquired: true
        )
      },
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogFinding: { .absent },
      signalMonitorFactory: { RecoveryNoopSignalMonitor() },
      cleanupPollLimit: 1
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["recovery", "inspect", "--json"],
      dependencies: dependencies
    )

    #expect(result.exitCode == 74)
    let object = try #require(
      try JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8)) as? [String: Any])
    #expect(object["nextAction"] as? String == "powervpn repair vendor-log --json")
    let measurement = try #require(object["measurement"] as? [String: Any])
    #expect(measurement["preflightFindings"] as? [String] == ["vendor_log_absent"])
  }
}

private let absentVendorLogPreflight = VendorXPCPreflightEvidence(
  guiProcessAbsent: true,
  helperProcessAbsent: true,
  otherVendorHelperProcessesAbsent: true,
  helperLaunchdInactive: true,
  dnsRecoveryFileAbsent: true,
  vendorLogRotationSafe: false,
  vendorLogFinding: .absent
)

private func repairField(_ result: UserProductCommandResult, _ key: String) throws -> Any? {
  let object = try JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
  return (object as? [String: Any])?[key]
}

private struct RepairHarness {
  let runner: RepairProcessRunner
  let dependencies: UserProductCommandDependencies
  let directory: URL

  init(
    findings: [VendorLogFinding],
    quiescent: Bool = true,
    leaseAvailable: Bool = true,
    approvalExitCode: Int32 = 0
  ) {
    directory = recoveryTemporaryDirectory()
    let runner = RepairProcessRunner(exitCode: approvalExitCode)
    self.runner = runner
    let sequence = RepairFindingSequence(findings)
    let base = recoveryDependencies(store: UserProductSessionStateStore(directory: directory))
    dependencies = UserProductCommandDependencies(
      loadConfiguration: base.loadConfiguration,
      processRunner: runner,
      stateStore: UserProductSessionStateStore(directory: directory),
      executablePath: base.executablePath,
      mutationLeaseAvailable: { leaseAvailable },
      systemStatus: base.systemStatus,
      proxyRunner: base.proxyRunner,
      recoveryRunner: base.recoveryRunner,
      credentialFileSafe: { true },
      helperArtifactSafe: { true },
      vendorLogFinding: { sequence.next() },
      vendorQuiescent: { quiescent },
      signalMonitorFactory: { RecoveryNoopSignalMonitor() },
      cleanupPollLimit: 1
    )
  }

  func repair() async throws -> UserProductCommandResult {
    defer { try? FileManager.default.removeItem(at: directory) }
    return try await runCurrentMachineUserProductCommand(
      ["repair", "vendor-log", "--json"],
      dependencies: dependencies
    )
  }
}

private final class RepairFindingSequence: @unchecked Sendable {
  private let lock = NSLock()
  private var findings: [VendorLogFinding]

  init(_ findings: [VendorLogFinding]) { self.findings = findings }

  func next() -> VendorLogFinding {
    lock.withLock { findings.count > 1 ? findings.removeFirst() : findings[0] }
  }
}

private final class RepairProcessRunner: UserProductProcessRunning, @unchecked Sendable {
  struct Call: Equatable {
    let executable: String
    let arguments: [String]
  }

  private let lock = NSLock()
  private let exitCode: Int32
  private var storedCalls: [Call] = []

  init(exitCode: Int32) { self.exitCode = exitCode }

  var calls: [Call] { lock.withLock { storedCalls } }

  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    lock.withLock { storedCalls.append(Call(executable: executable, arguments: arguments)) }
    return UserProductProcessResult(started: true, exitCode: exitCode, output: "")
  }
}
