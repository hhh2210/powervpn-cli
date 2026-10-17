import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal

@Suite struct UserProductCommandTests {
  @Test func ephemeralSSHResolvesTargetAndPreservesRemoteExitCode() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let runner = UserProductTestProcessRunner { _, arguments, io, _ in
      #expect(io == .inherited)
      #expect(arguments.contains("thu52"))
      #expect(arguments.suffix(2) == ["hostname", "--version"])
      let joined = arguments.joined(separator: " ")
      #expect(joined.contains("internal-session-proxy"))
      #expect(!joined.contains("Login Resource 52"))
      #expect(!joined.contains("m2"))
      if let state = try? store.load() {
        _ = try? store.update(sessionID: state.sessionID) {
          $0.phase = .disconnected
          $0.cleanupVerified = true
        }
      }
      return .init(started: true, exitCode: 23, output: "")
    }
    let result = try await runCurrentMachineUserProductCommand(
      ["ssh", "thu52", "--", "hostname", "--version"],
      dependencies: dependencies(runner: runner, store: store)
    )

    #expect(result.exitCode == 23)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError.isEmpty)
  }

  @Test func internalProxyResolvesResourceWithoutExposingItInPublicArgv() async throws {
    let trace = UserProductProxyTrace(
      result: ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
    )
    let result = try await runCurrentMachineUserProductCommand(
      ["internal-proxy", "thu52", "192.0.2.52", "22"],
      dependencies: dependencies(proxyRunner: trace.run)
    )

    #expect(result.exitCode == 0)
    #expect(
      trace.arguments
        == [
          "proxy", "ssh", "--resource-display-name", "Login Resource 52",
          "--ssh-target", "thu52", "192.0.2.52", "22", "--non-interactive",
        ])
  }

  @Test func internalProxyHumanizesCatalogFailure() async throws {
    let trace = UserProductProxyTrace(
      result: ProxyCommandResult(
        standardOutput: "",
        standardError:
          "tunnel_open_failed:resource_catalog_rejected:catalog=scope.integration_info_missing\n",
        exitCode: 69
      )
    )
    let result = try await runCurrentMachineUserProductCommand(
      ["internal-proxy", "thu52", "192.0.2.52", "22"],
      dependencies: dependencies(proxyRunner: trace.run)
    )

    #expect(result.exitCode == 69)
    #expect(result.standardError.contains("incomplete resource list"))
    #expect(!result.standardError.contains("integration_info"))
  }

  @Test func sessionProxyPublishesVerifiedCleanupReceiptAfterOwnerExit() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let sessionID = UUID().uuidString.lowercased()
    try store.save(
      UserProductSessionState(
        sessionID: sessionID,
        target: "thu52",
        controlPath: uniqueSSHSocketPath(),
        phase: .connected,
        ownerPID: 4321
      )
    )
    let trace = UserProductProxyTrace(
      result: ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", sessionID, "thu52", "192.0.2.52", "22"],
      dependencies: dependencies(store: store, proxyRunner: trace.run)
    )

    #expect(result.exitCode == 0)
    let state = try store.load()
    #expect(state?.phase == .disconnected)
    #expect(state?.cleanupVerified == true)
  }

  @Test func sessionProxyTreatsPostSSHNCExitAsVerifiedStreamClose() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let sessionID = UUID().uuidString.lowercased()
    try store.save(
      UserProductSessionState(
        sessionID: sessionID,
        target: "thu52",
        controlPath: uniqueSSHSocketPath(),
        phase: .connected
      )
    )
    let trace = UserProductProxyTrace(
      result: ProxyCommandResult(
        standardOutput: "",
        standardError: "child_failed\n",
        exitCode: 1
      )
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", sessionID, "thu52", "192.0.2.52", "22"],
      dependencies: dependencies(store: store, proxyRunner: trace.run)
    )

    #expect(result.standardError.isEmpty)
    let state = try store.load()
    #expect(state?.phase == .disconnected)
    #expect(state?.cleanupVerified == true)
    #expect(state?.failure == nil)
  }

  @Test func sessionProxyTreatsControlledSIGHUPAsVerifiedDisconnect() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let sessionID = UUID().uuidString.lowercased()
    try store.save(
      UserProductSessionState(
        sessionID: sessionID,
        target: "thu52",
        controlPath: uniqueSSHSocketPath(),
        phase: .disconnecting,
        ownerPID: 4321
      )
    )
    let trace = UserProductProxyTrace(
      result: ProxyCommandResult(
        standardOutput: "",
        standardError: "cancelled\n",
        exitCode: 130
      )
    )

    let result = try await runCurrentMachineUserProductCommand(
      ["internal-session-proxy", sessionID, "thu52", "192.0.2.52", "22"],
      dependencies: dependencies(store: store, proxyRunner: trace.run)
    )

    #expect(result.standardError.isEmpty)
    let state = try store.load()
    #expect(state?.phase == .disconnected)
    #expect(state?.cleanupVerified == true)
    #expect(state?.failure == nil)
  }

  @Test func upCreatesReadyMasterAndSecondUpIsIdempotent() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let socket = uniqueSSHSocketPath()
    let checkCount = LockedCounter()
    let runner = UserProductTestProcessRunner { _, arguments, _, _ in
      if arguments.first == "-G" {
        return .init(started: true, exitCode: 0, output: sshConfiguration(socket: socket))
      }
      if arguments.contains("check") {
        let count = checkCount.next()
        return .init(
          started: true,
          exitCode: count == 0 ? 255 : 0,
          output: count == 0 ? "" : "Master running (pid=4321)\n"
        )
      }
      if arguments.contains("-f") {
        #expect(arguments.contains("ControlMaster=yes"))
        #expect(arguments.joined(separator: " ").contains("internal-session-proxy"))
        return .init(started: true, exitCode: 0, output: "")
      }
      Issue.record("unexpected SSH invocation: \(arguments)")
      return .init(started: false, exitCode: 70, output: "")
    }
    let environment = dependencies(runner: runner, store: store)

    let first = try await runCurrentMachineUserProductCommand(
      ["up", "thu52"],
      dependencies: environment
    )
    #expect(first.exitCode == 0)
    #expect(first.standardOutput.contains("Session: active"))
    let loaded = try store.load()
    let state = try #require(loaded)
    #expect(state.phase == .connected)
    #expect(state.ownerPID == 4321)

    let second = try await runCurrentMachineUserProductCommand(
      ["up", "thu52"],
      dependencies: environment
    )
    #expect(second.exitCode == 0)
    #expect(second.standardOutput.contains("already active"))
  }

  @Test func downWaitsForSessionProxyCleanupReceipt() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu52",
      controlPath: uniqueSSHSocketPath(),
      phase: .connected,
      ownerPID: 4321
    )
    try store.save(state)
    let runner = UserProductTestProcessRunner { _, arguments, _, _ in
      if arguments.contains("check") {
        return .init(started: true, exitCode: 0, output: "Master running (pid=4321)\n")
      }
      if arguments.contains("exit") {
        return .init(started: true, exitCode: 0, output: "Exit request sent.\n")
      }
      return .init(started: false, exitCode: 70, output: "")
    }
    let result = try await runCurrentMachineUserProductCommand(
      ["down"],
      dependencies: dependencies(
        runner: runner,
        store: store,
        mutationLeaseAvailable: { false },
        sleepMilliseconds: { _ in
          _ = try? store.update(sessionID: state.sessionID) {
            $0.phase = .disconnected
            $0.cleanupVerified = true
          }
        },
        cleanupPollLimit: 2
      )
    )

    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("Cleanup: verified"))
    #expect(try store.load() == nil)
  }

  @Test func statusQuarantinesStaleStateWithoutClaimingCleanup() async throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu52",
      controlPath: uniqueSSHSocketPath(),
      phase: .connected,
      ownerPID: 99999
    )
    try store.save(state)
    let runner = UserProductTestProcessRunner { _, _, _, _ in
      .init(started: true, exitCode: 255, output: "")
    }
    let result = try await runCurrentMachineUserProductCommand(
      ["status"],
      dependencies: dependencies(
        runner: runner,
        store: store,
        mutationLeaseAvailable: { true }
      )
    )

    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("PowerVPN: cleanup_failed"))
    #expect(result.standardOutput.contains("cleanup is not verified"))
    let quarantined = try store.load()
    #expect(quarantined?.phase == .failed)
    #expect(quarantined?.cleanupVerified == false)
  }

  @Test func sessionStateStoreRejectsReadableStateFile() throws {
    let directory = temporaryStateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = UserProductSessionStateStore(directory: directory)
    let state = UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(),
      target: "thu52",
      controlPath: uniqueSSHSocketPath(),
      phase: .connected
    )
    try store.save(state)
    #expect(chmod(store.statePath, 0o644) == 0)
    #expect(throws: UserProductSessionStoreError.unsafeStateFile) {
      _ = try store.load()
    }
  }
}

private final class UserProductTestProcessRunner: UserProductProcessRunning,
  @unchecked Sendable
{
  typealias Handler =
    @Sendable (
      String, [String], UserProductProcessIO, Int
    ) -> UserProductProcessResult

  private let lock = NSLock()
  private let handler: Handler
  private var count = 0

  init(handler: @escaping Handler) { self.handler = handler }

  func run(
    executable: String,
    arguments: [String],
    io: UserProductProcessIO
  ) -> UserProductProcessResult {
    let invocation = lock.withLock { () -> Int in
      defer { count += 1 }
      return count
    }
    return handler(executable, arguments, io, invocation)
  }
}

private final class UserProductProxyTrace: @unchecked Sendable {
  private let lock = NSLock()
  private let result: ProxyCommandResult
  private var recordedArguments: [String] = []

  init(result: ProxyCommandResult) { self.result = result }

  func run(_ arguments: [String]) async throws -> ProxyCommandResult {
    lock.withLock { recordedArguments = arguments }
    return result
  }

  var arguments: [String] { lock.withLock { recordedArguments } }
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func next() -> Int {
    lock.withLock {
      defer { value += 1 }
      return value
    }
  }
}

private func dependencies(
  runner: any UserProductProcessRunning = UserProductTestProcessRunner { _, _, _, _ in
    .init(started: true, exitCode: 0, output: "")
  },
  store: UserProductSessionStateStore = UserProductSessionStateStore(
    directory: temporaryStateDirectory()
  ),
  mutationLeaseAvailable: @escaping @Sendable () -> Bool = { true },
  proxyRunner: @escaping @Sendable ([String]) async throws -> ProxyCommandResult = { _ in
    ProxyCommandResult(standardOutput: "", standardError: "", exitCode: 0)
  },
  sleepMilliseconds: @escaping @Sendable (Int) async -> Void = { _ in },
  cleanupPollLimit: Int = 1
) -> UserProductCommandDependencies {
  UserProductCommandDependencies(
    loadConfiguration: { try userProductTestConfiguration() },
    processRunner: runner,
    stateStore: store,
    executablePath: "/Users/test/.local/bin/powervpn",
    mutationLeaseAvailable: mutationLeaseAvailable,
    systemStatus: userProductTestSystemStatus,
    proxyRunner: proxyRunner,
    sleepMilliseconds: sleepMilliseconds,
    cleanupPollLimit: cleanupPollLimit
  )
}

private func userProductTestConfiguration() throws -> PowerVPNTargetsConfiguration {
  try PowerVPNTargetsConfiguration.decode(
    Data(
      """
      {"portalOrigin":"https://192.0.2.1:4443","targets":{"thu52":{"host":"192.0.2.52","user":"synthetic-user","resource":"Login Resource 52"}}}
      """.utf8
    )
  )
}

private func userProductTestSystemStatus() -> PowerVPNStatus {
  PowerVPNStatus(
    appVersion: "3.2.1",
    appBuild: "24572",
    appArchitectures: ["x86_64"],
    appRunning: false,
    helper: HelperState(
      state: "not running",
      pid: nil,
      runs: 1,
      successiveCrashes: 0,
      lastTerminatingSignal: nil
    ),
    tunnel: TunnelLogState(
      health: .stopped,
      latestEvent: "helper not running",
      historicalHint: false
    )
  )
}

private func temporaryStateDirectory() -> URL {
  FileManager.default.temporaryDirectory
    .appendingPathComponent("powervpn-user-product-tests-\(UUID().uuidString)")
}

private func uniqueSSHSocketPath() -> String {
  FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".ssh/test-powervpn-\(UUID().uuidString).sock").path
}

private func sshConfiguration(socket: String) -> String {
  """
  host thu52
  user synthetic-user
  hostname 192.0.2.52
  port 22
  controlmaster auto
  controlpath \(socket)
  """
}
