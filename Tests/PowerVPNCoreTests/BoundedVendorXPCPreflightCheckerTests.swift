import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct BoundedVendorXPCPreflightCheckerTests {
  @Test func safeFixtureUsesOneFixedBoundedProcessSnapshotAndFixedPaths() async {
    let paths = PreflightPathTrace([
      InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
      InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: .absent,
    ])
    let runner = PreflightCommandRunner([success(preflightPS("/usr/bin/other"))])
    let evidence = await checker(runner: runner, paths: paths).check(
      generation: preflightColdGeneration,
      timeoutMilliseconds: 613
    )

    #expect(evidence.safeToProbe)
    #expect(runner.commands == [.surgeProcesses])
    #expect(runner.timeouts == [613])
    #expect(NetworkCleanupCommand.surgeProcesses.request.executable == "/bin/ps")
    #expect(
      NetworkCleanupCommand.surgeProcesses.request.arguments
        == ["-axo", "pid=,lstart=,command="])
    #expect(NetworkCleanupCommand.surgeProcesses.request.timeoutMilliseconds == 2_000)
    #expect(NetworkCleanupCommand.surgeProcesses.request.stdoutLimitBytes == 8_388_608)
    #expect(NetworkCleanupCommand.surgeProcesses.request.stderrLimitBytes == 65_536)
    #expect(
      paths.paths == [
        InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath,
        InstalledBoundedVendorXPCPreflightChecker.vendorLogPath,
      ])

    let legacyRunner = PreflightCommandRunner([success(preflightPS("/usr/bin/other"))])
    _ = await checker(runner: legacyRunner).check(generation: preflightColdGeneration)
    #expect(legacyRunner.timeouts == [2_000])
  }

  @Test func exactExecutableNamesDetectGUIAndEveryVendorHelper() async {
    let output = [
      preflightPS("/Applications/PowerVPN.app/Contents/MacOS/PowerVPN", pid: 10),
      preflightPS("/Library/PrivilegedHelperTools/com.leadsec.charon-xpc", pid: 11),
      preflightPS("/Library/PrivilegedHelperTools/com.leadsec.ipsec-xpc", pid: 12),
      preflightPS("/Library/PrivilegedHelperTools/com.leadsec.sh-xpc", pid: 13),
    ].joined()
    let evidence = await checker(
      runner: PreflightCommandRunner([success(output)])
    ).check(generation: preflightColdGeneration)

    #expect(!evidence.guiProcessAbsent)
    #expect(!evidence.helperProcessAbsent)
    #expect(!evidence.otherVendorHelperProcessesAbsent)

    let argumentOnly = await checker(
      runner: PreflightCommandRunner([
        success(preflightPS("/usr/bin/printf", arguments: "PowerVPN com.leadsec.charon-xpc"))
      ])
    ).check(generation: preflightColdGeneration)
    #expect(argumentOnly.guiProcessAbsent)
    #expect(argumentOnly.helperProcessAbsent)
    #expect(argumentOnly.otherVendorHelperProcessesAbsent)
  }

  @Test func guiApplicationGateAndPathShapesFailClosed() async {
    let gui = await checker(
      runner: PreflightCommandRunner([success(preflightPS("/usr/bin/other"))]),
      guiApplicationRunning: true
    ).check(generation: preflightColdGeneration)
    #expect(!gui.guiProcessAbsent)

    let dnsPresent = PreflightPathTrace([
      InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .regularFile(size: 0),
      InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: .regularFile(
        size: InstalledBoundedVendorXPCPreflightChecker.vendorLogRotationThreshold),
    ])
    let boundedLog = await checker(
      runner: PreflightCommandRunner([success(preflightPS("/usr/bin/other"))]),
      paths: dnsPresent
    ).check(generation: preflightColdGeneration)
    #expect(!boundedLog.dnsRecoveryFileAbsent)
    #expect(boundedLog.vendorLogRotationSafe)

    let unsafeLog = PreflightPathTrace([
      InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
      InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: .regularFile(
        size: InstalledBoundedVendorXPCPreflightChecker.vendorLogRotationThreshold + 1),
    ])
    let oversized = await checker(
      runner: PreflightCommandRunner([success(preflightPS("/usr/bin/other"))]),
      paths: unsafeLog
    ).check(generation: preflightColdGeneration)
    #expect(!oversized.vendorLogRotationSafe)
  }

  @Test func timeoutOversizeAndMalformedOutputCollapseWithoutRawValues() async {
    let marker = "sensitive-preflight-output"
    let results = [
      failed(.timedOut, marker: marker),
      failed(.stdoutLimitExceeded, marker: marker),
      success(""),
      success("malformed \(marker)\n"),
      success("100 aaa bbb 99 25:61:61 -123 /usr/bin/other\n"),
    ]
    for result in results {
      let evidence = await checker(
        runner: PreflightCommandRunner([result])
      ).check(generation: preflightColdGeneration)
      #expect(!evidence.guiProcessAbsent)
      #expect(!evidence.helperProcessAbsent)
      #expect(!evidence.otherVendorHelperProcessesAbsent)
      #expect(!String(describing: evidence).contains(marker))
    }
  }
}

private func checker(
  runner: PreflightCommandRunner,
  guiApplicationRunning: Bool = false,
  paths: PreflightPathTrace = PreflightPathTrace([
    InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
    InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: .absent,
  ])
) -> InstalledBoundedVendorXPCPreflightChecker {
  InstalledBoundedVendorXPCPreflightChecker(
    runner: runner,
    guiApplicationRunning: { guiApplicationRunning },
    inspectPath: paths.inspect
  )
}

private final class PreflightCommandRunner: @unchecked Sendable,
  NetworkCleanupCommandRunning
{
  private let lock = NSLock()
  private var results: [BoundedCommandResult]
  private var storedCommands: [NetworkCleanupCommand] = []
  private var storedTimeouts: [Int] = []

  init(_ results: [BoundedCommandResult]) { self.results = results }

  func run(
    _ command: NetworkCleanupCommand,
    timeoutMilliseconds: Int
  ) async -> BoundedCommandResult {
    lock.withLock {
      storedCommands.append(command)
      storedTimeouts.append(timeoutMilliseconds)
      return results.isEmpty ? .immediate(.launchFailed) : results.removeFirst()
    }
  }

  var commands: [NetworkCleanupCommand] { lock.withLock { storedCommands } }
  var timeouts: [Int] { lock.withLock { storedTimeouts } }
}

private final class PreflightPathTrace: @unchecked Sendable {
  private let lock = NSLock()
  private let observations: [String: VendorXPCPreflightPathObservation]
  private var storedPaths: [String] = []

  init(_ observations: [String: VendorXPCPreflightPathObservation]) {
    self.observations = observations
  }

  func inspect(_ path: String) -> VendorXPCPreflightPathObservation {
    lock.withLock {
      storedPaths.append(path)
      return observations[path] ?? .unavailable
    }
  }

  var paths: [String] { lock.withLock { storedPaths } }
}

private let preflightColdGeneration = VendorHelperGenerationSnapshot(
  launchdObserved: true, running: false, inactiveConfirmed: true,
  activeCount: 0, pid: nil, runs: 7)

private func preflightPS(
  _ executable: String,
  pid: Int = 100,
  arguments: String = ""
) -> String {
  "\(pid) Tue Aug 11 12:34:56 2026 \(executable) \(arguments)\n"
}

private func success(_ output: String) -> BoundedCommandResult {
  BoundedCommandResult(
    outcome: .exited, started: true, exitStatus: 0,
    stdout: Data(output.utf8), stderr: Data(),
    terminationRequested: false, killRequested: false, reaped: true)
}

private func failed(
  _ outcome: BoundedCommandOutcome,
  marker: String
) -> BoundedCommandResult {
  BoundedCommandResult(
    outcome: outcome, started: true, exitStatus: nil,
    stdout: Data(marker.utf8), stderr: Data(marker.utf8),
    terminationRequested: true, killRequested: false, reaped: true)
}
