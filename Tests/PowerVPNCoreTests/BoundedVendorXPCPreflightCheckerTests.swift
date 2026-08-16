import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct BoundedVendorXPCPreflightCheckerTests {
  @Test func safeFixtureUsesOneFixedBoundedProcessSnapshotAndFixedPaths() async {
    let paths = PreflightPathTrace([
      InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
      InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: .regularFile(size: 0),
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

  @Test func vendorLogMetadataGateIsExactAndFailsBeforeXPCSubmission() async throws {
    let root0600 = InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
      mode: mode_t(S_IFREG | 0o600),
      size: 0,
      ownerUID: 0,
      ownerGID: 0
    )
    #expect(root0600 == .regularFile(size: 0))
    #expect(
      InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
        mode: mode_t(S_IFDIR | 0o600), size: 0, ownerUID: 0, ownerGID: 0
      ) == .unsupported)
    #expect(
      InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
        mode: mode_t(S_IFREG | 0o600), size: -1, ownerUID: 0, ownerGID: 0
      ) == .unsupported)
    let accepted = await checker(
      runner: PreflightCommandRunner([success(preflightPS("/usr/bin/other"))]),
      paths: PreflightPathTrace([
        InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
        InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: root0600,
      ])
    ).check(generation: preflightColdGeneration)
    #expect(accepted.safeToProbe)

    let rejectedObservations = [
      InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
        mode: mode_t(S_IFREG | 0o644),
        size: 0,
        ownerUID: 0,
        ownerGID: 0
      ),
      InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
        mode: mode_t(S_IFREG | 0o600),
        size: 0,
        ownerUID: 501,
        ownerGID: 0
      ),
      InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
        mode: mode_t(S_IFREG | 0o600),
        size: 0,
        ownerUID: 0,
        ownerGID: 20
      ),
      VendorXPCPreflightPathObservation.absent,
      .unavailable,
      .unsupported,
    ]
    #expect(rejectedObservations[0] == .unsafePermissions)
    #expect(rejectedObservations[1] == .unsafeOwnership)
    #expect(rejectedObservations[2] == .unsafeOwnership)

    for observation in rejectedObservations {
      let installedChecker = checker(
        runner: PreflightCommandRunner([success(preflightPS("/usr/bin/other"))]),
        paths: PreflightPathTrace([
          InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
          InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: observation,
        ])
      )
      let transport = ProbeTransport(
        evidence: VendorXPCGetVersionEvidence(
          outcome: .accepted,
          connectionCancelRequested: true
        ),
        peerPID: 400
      )
      let result = await VendorXPCReachabilityProbe(
        transport: transport,
        generationObserver: ProbeGenerationObserver([preflightColdGeneration]),
        preflightChecker: installedChecker
      ).probe(timeoutMilliseconds: 500)

      #expect(result.status == .preflightBlocked)
      #expect(!result.probePerformed)
      #expect(await transport.callCount == 0)
    }
  }

  @Test func rejectedMetadataAndReportEncodingRemainValueFree() async throws {
    let observation = InstalledBoundedVendorXPCPreflightChecker.classifyPathMetadata(
      mode: mode_t(S_IFREG | 0o644),
      size: 9_876,
      ownerUID: 501,
      ownerGID: 20
    )
    #expect(observation == .unsafeOwnership)
    #expect(String(describing: observation) == "unsafeOwnership")

    let evidence = await checker(
      runner: PreflightCommandRunner([success(preflightPS("/usr/bin/other"))]),
      paths: PreflightPathTrace([
        InstalledBoundedVendorXPCPreflightChecker.dnsRecoveryPath: .absent,
        InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: observation,
      ])
    ).check(generation: preflightColdGeneration)
    let encoded = String(
      decoding: try JSONEncoder().encode(evidence),
      as: UTF8.self
    )

    #expect(!evidence.vendorLogRotationSafe)
    #expect(!evidence.safeToProbe)
    for forbidden in ["/var/log/vsgvpn.log", "0644", "420", "501", "9876"] {
      #expect(!encoded.contains(forbidden))
    }
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
    InstalledBoundedVendorXPCPreflightChecker.vendorLogPath: .regularFile(size: 0),
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
