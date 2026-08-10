import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupObserverTests {
  @Test func boundedGenerationObserverUsesOnlyFixedHelperCommand() async {
    let helper = success(helperFixture(running: false, pid: nil, runs: 10))
    let runner = FixtureNetworkCleanupRunner([.helperGeneration: [helper]])
    let generation = await InstalledBoundedVendorHelperGenerationObserver(
      runner: runner
    ).observe()

    #expect(generation.exactInactive)
    #expect(runner.observedCommands == [.helperGeneration])
  }

  @Test func boundedGenerationObserverFailsClosedWithoutOutput() async {
    let marker = "sensitive-generation-output"
    let failed = BoundedCommandResult(
      outcome: .timedOut,
      started: true,
      exitStatus: nil,
      stdout: Data(marker.utf8),
      stderr: Data(marker.utf8),
      terminationRequested: true,
      killRequested: false,
      reaped: true
    )
    let observer = InstalledBoundedVendorHelperGenerationObserver(
      runner: FixtureNetworkCleanupRunner([.helperGeneration: [failed]])
    )
    let generation = await observer.observe()

    #expect(!generation.launchdObserved)
    #expect(!String(describing: generation).contains(marker))
  }

  @Test func fixtureCaptureUsesOnlyFixedCommandsAndProducesCompleteSnapshot() async {
    let runner = FixtureNetworkCleanupRunner(successfulResponses())
    let snapshot = await InstalledNetworkCleanupObserver(runner: runner).capture(
      window: NetworkCleanupCaptureWindow(keyData: Data(repeating: 3, count: 32))
    )

    #expect(snapshot.complete)
    #expect(snapshot.defaultRoute.isObserved)
    #expect(snapshot.dns.isObserved)
    #expect(snapshot.interfaces.utunCount == 1)
    #expect(snapshot.ipv4Routes.persistent.itemCount == 2)
    #expect(snapshot.ipv6Routes.persistent.itemCount == 2)
    #expect(snapshot.surge.mainProcessCount == 1)
    #expect(snapshot.helperGeneration.exactInactive)
    #expect(
      runner.observedCommands == [
        .helperGeneration, .surgeProcesses, .defaultRoute, .dns, .interfaces,
        .ipv4Routes, .ipv6Routes, .surgeProcesses, .helperGeneration,
      ])
  }

  @Test func commandCatalogIsAbsoluteBoundedAndContainsNoNetworkClientOrShell() {
    let forbidden = ["curl", "nc", "ssh", "surge-cli", "sh", "zsh", "bash"]
    for command in NetworkCleanupCommand.allCases {
      let request = command.request
      #expect(request.isValid)
      #expect(request.executable.hasPrefix("/"))
      #expect((1...8_388_608).contains(request.stdoutLimitBytes))
      #expect(request.stderrLimitBytes == 65_536)
      #expect(request.timeoutMilliseconds == 2_000)
      #expect(!forbidden.contains(URL(fileURLWithPath: request.executable).lastPathComponent))
    }
  }

  @Test func failedAndOversizedCommandsCollapseWithoutRawOutput() async {
    let marker = "sensitive-command-output"
    var responses = successfulResponses()
    responses[.defaultRoute] = [
      BoundedCommandResult(
        outcome: .stdoutLimitExceeded,
        started: true,
        exitStatus: 9,
        stdout: Data(marker.utf8),
        stderr: Data(marker.utf8),
        terminationRequested: true,
        killRequested: false,
        reaped: true
      )
    ]
    let snapshot = await InstalledNetworkCleanupObserver(
      runner: FixtureNetworkCleanupRunner(responses)
    ).capture(window: NetworkCleanupCaptureWindow())

    #expect(!snapshot.complete)
    #expect(snapshot.defaultRoute.state == .outputTooLarge)
    #expect(snapshot.defaultRoute.sha256 == nil)
    #expect(!String(describing: snapshot).contains(marker))
  }

  @Test func surgeOrHelperChangeInsideCaptureFailsClosed() async {
    var surgeResponses = successfulResponses()
    surgeResponses[.surgeProcesses] = [
      success(surgeFixture(pid: 100)), success(surgeFixture(pid: 200)),
    ]
    let surge = await InstalledNetworkCleanupObserver(
      runner: FixtureNetworkCleanupRunner(surgeResponses)
    ).capture(window: NetworkCleanupCaptureWindow())
    #expect(!surge.complete)
    #expect(surge.surge.fingerprint.state == .changedDuringCapture)

    var helperResponses = successfulResponses()
    helperResponses[.helperGeneration] = [
      success(helperFixture(running: false, pid: nil, runs: 10)),
      success(helperFixture(running: true, pid: 400, runs: 11)),
    ]
    let helper = await InstalledNetworkCleanupObserver(
      runner: FixtureNetworkCleanupRunner(helperResponses)
    ).capture(window: NetworkCleanupCaptureWindow())
    #expect(!helper.complete)
    #expect(helper.helperObservationState == .changedDuringCapture)
  }
}

private final class FixtureNetworkCleanupRunner: @unchecked Sendable,
  NetworkCleanupCommandRunning
{
  private let lock = NSLock()
  private var responses: [NetworkCleanupCommand: [BoundedCommandResult]]
  private var calls: [NetworkCleanupCommand] = []

  init(_ responses: [NetworkCleanupCommand: [BoundedCommandResult]]) {
    self.responses = responses
  }

  func run(_ command: NetworkCleanupCommand) async -> BoundedCommandResult {
    lock.withLock {
      calls.append(command)
      guard var queue = responses[command], !queue.isEmpty else {
        return .immediate(.launchFailed)
      }
      let result = queue.removeFirst()
      responses[command] = queue
      return result
    }
  }

  var observedCommands: [NetworkCleanupCommand] { lock.withLock { calls } }
}

private func successfulResponses() -> [NetworkCleanupCommand: [BoundedCommandResult]] {
  let helper = success(helperFixture(running: false, pid: nil, runs: 10))
  let surge = success(surgeFixture(pid: 100))
  return [
    .helperGeneration: [helper, helper],
    .surgeProcesses: [surge, surge],
    .defaultRoute: [
      success(
        "destination: default\ngateway: 192.0.2.1\ninterface: utun8\nflags: <UP,GATEWAY>\n")
    ],
    .dns: [success("DNS configuration\nresolver #1\nnameserver[0] : 192.0.2.53\n")],
    .interfaces: [
      success(
        "en0: flags=1<UP> mtu 1500\n  status: active\nutun8: flags=1<UP> mtu 1380\n  status: active\n"
      )
    ],
    .ipv4Routes: [
      success(
        routeFixture(
          banner: "Internet:",
          rows: ["default 192.0.2.1 UGScg en0", "10.0.0/8 link#9 UGScI utun8"]
        ))
    ],
    .ipv6Routes: [
      success(
        routeFixture(
          banner: "Internet6:",
          rows: ["default fe80::1%en0 UGcg en0", "2001:db8::/32 link#9 UCS utun8"]
        ))
    ],
  ]
}

private func success(_ text: String) -> BoundedCommandResult {
  BoundedCommandResult(
    outcome: .exited,
    started: true,
    exitStatus: 0,
    stdout: Data(text.utf8),
    stderr: Data(),
    terminationRequested: false,
    killRequested: false,
    reaped: true
  )
}

private func helperFixture(running: Bool, pid: Int?, runs: Int) -> String {
  """
  system/com.leadsec.charon-xpc = {
    active count = \(running ? 1 : 0)
    state = \(running ? "running" : "not running")
  \(pid.map { "  pid = \($0)\n" } ?? "")  runs = \(runs)
  }
  """
}

private func surgeFixture(pid: Int) -> String {
  """
  \(pid) Tue Aug 11 12:34:56 2026 /Applications/Surge.app/Contents/MacOS/Surge
  101 Tue Aug 11 12:34:56 2026 /Applications/Surge.app/X/com.nssurge.surge-mac.ne
  102 Tue Aug 11 12:34:56 2026 /Library/PrivilegedHelperTools/com.nssurge.surge-mac.helper
  """
}

private func routeFixture(banner: String, rows: [String]) -> String {
  "Routing tables\n\(banner)\nDestination Gateway Flags Netif Expire\n"
    + rows.joined(separator: "\n") + "\n"
}
