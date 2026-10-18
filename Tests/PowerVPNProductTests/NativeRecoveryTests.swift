import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct NativeRecoveryTests {
  @Test(arguments: [
    (NativeTunnelFailure.portalUnavailable, Int32(75), 2),
    (.resourceUnavailable, Int32(75), 2), (.portalRejected, Int32(77), 1),
  ])
  func runDistinguishesTransientPortalFailuresFromCredentials(
    failure: NativeTunnelFailure, expectedExit: Int32, expectedStarts: Int
  ) async throws {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    let runner = NativeFailedStartRunner(store: store, failure: failure.rawValue)
    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: UserProductCommandDependencies(
        loadConfiguration: { try config(.native) }, processRunner: runner, stateStore: store,
        mutationLeaseAvailable: { true }, sleepMilliseconds: { _ in }))
    #expect(result.exitCode == expectedExit)
    #expect(runner.starts == expectedStarts)
    if expectedExit == 75 { #expect(!result.standardError.contains("credentials.env")) }
  }

  @Test func legacyVendorQuarantineSurvivesAConfigurationSwitchToNative() async throws {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    var state = staleState(backend: .vendor)
    state.backend = nil
    try store.save(state)
    let dependencies = deps(
      store: store, configured: .native,
      recover: { _ in
        Issue.record("native recovery must not touch a legacy vendor owner")
        return true
      })
    let result = try await runCurrentMachineUserProductCommand(["down"], dependencies: dependencies)
    #expect(result.exitCode == 74)
    #expect(try store.load() == state)
  }

  @Test func unverifiedPortalOpenCannotResetTheNativeStartRetryBudget() async throws {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    let runner = NativeFailedStartRunner(store: store, failure: "cleanup_unproven", cleaned: false)
    let result = try await runCurrentMachineUserProductCommand(
      ["run", "thu21", "--", "hostname"],
      dependencies: UserProductCommandDependencies(
        loadConfiguration: { try config(.native) }, processRunner: runner, stateStore: store,
        mutationLeaseAvailable: { true },
        acquireMutationLease: { try ProductMutationLease.acquire(stateDirectory: store.directory) },
        sleepMilliseconds: { _ in }, nativeRecoverStale: { _ in true }))
    #expect(result.exitCode == 75)
    #expect(runner.starts == 2)
    #expect(try store.load()?.cleanupVerified == false)
    #expect(result.standardError.contains("native_cleanup_unproven"))
  }

  @Test func recoveryHoldsMutationLeaseAndRetainsPortalUncertaintyAcrossBackendSwitch() async throws
  {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    try store.save(staleState(backend: .native))
    let dependencies = deps(
      store: store, configured: .vendor,
      recover: { _ in
        #expect(throws: ProductMutationLeaseError.alreadyHeld) {
          try ProductMutationLease.acquire(stateDirectory: store.directory)
        }
        return true
      })
    let result = try await runCurrentMachineUserProductCommand(["down"], dependencies: dependencies)
    #expect(result.exitCode == 0)
    #expect(result.standardOutput.contains("Original Portal cleanup: unverified"))
    #expect(!result.standardOutput.contains("Cleanup: verified"))
    let loaded = try store.load()
    let retained = try #require(loaded)
    #expect(retained.nativeLocalRecoveryVerified == true)
    #expect(retained.cleanupVerified == false)
    #expect(retained.reconnectPermitted)
    let inspection = try await runCurrentMachineUserProductCommand(
      ["recovery", "inspect", "--json"], dependencies: dependencies)
    #expect(inspection.standardOutput.contains("\"nativePortalCleanupVerified\" : false"))
    #expect(inspection.standardOutput.contains("\"nativeLocalCleanupVerified\" : true"))
  }

  @Test func recoveryCannotRaceAStandaloneProxy() async throws {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    let state = staleState(backend: .native)
    try store.save(state)
    let lease = try ProductMutationLease.acquire(stateDirectory: store.directory)
    defer { withExtendedLifetime(lease) {} }
    let dependencies = deps(
      store: store,
      recover: { _ in
        Issue.record("busy recovery must not mutate")
        return true
      })
    let result = try await runCurrentMachineUserProductCommand(["down"], dependencies: dependencies)
    #expect(result.exitCode == 75)
    #expect(try store.load() == state)
  }

  @Test func localRecoveryArchivesOriginalFailureBeforeRemovingSession() async throws {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    let state = staleState(backend: .native)
    try store.save(state)
    let failure = try await clearNativeLeftovers(
      state, removeState: true, dependencies: deps(store: store))
    #expect(failure == nil)
    #expect(try store.load() == nil)
    let archive = store.directory.appendingPathComponent("native-recovery-\(state.sessionID).json")
    let saved = try JSONDecoder().decode(
      UserProductSessionState.self, from: Data(contentsOf: archive))
    #expect(saved.failure == "cleanup_unproven")
    #expect(saved.cleanupVerified == false)
    #expect(saved.nativeLocalRecoveryVerified == true)
    var metadata = stat()
    #expect(lstat(archive.path, &metadata) == 0)
    #expect(metadata.st_mode & 0o777 == 0o600)
  }

  @Test func failedOpenDoesNotLaunderCleanupOrMutationEvidence() async throws {
    let report = NativeTunnelOpenFailure(
      failure: .ikeFailed,
      helperMutationRequested: true, serverContactRequested: true, cleanupVerified: false)
    let failure = nativeOpenFailure(report)
    #expect(failure.helperMutationRequested)
    #expect(failure.serverContactRequested)
    #expect(!failure.cleanupVerified)
    let result = await openAndRun(
      request: try parseProxySSHInvocation(proxySSHArguments).request, startupBudget: .start(),
      cleanupBudgetFactory: { .start() }, runtime: { _, _ in .failed(failure) },
      operation: { _ in
        Issue.record("failed open must never start SSH")
        return .cancelled
      })
    guard case .failure(_, let code, _, let mutated, let contacted, let cleaned, _) = result else {
      Issue.record("expected failed execution")
      return
    }
    #expect(code == 74 && mutated && contacted && !cleaned)
  }

  @Test func delayedProxyChecksOwnershipAfterAcquiringTheLease() async throws {
    let store = try makeStore()
    defer { try? FileManager.default.removeItem(at: store.directory) }
    let result = await openNativeProxyTunnel(
      configuration: try config(.native),
      request: try parseProxySSHInvocation(proxySSHArguments).request,
      sessionStillOwned: {
        #expect(throws: ProductMutationLeaseError.alreadyHeld) {
          try ProductMutationLease.acquire(stateDirectory: store.directory)
        }
        return false
      },
      acquireMutationLease: { try ProductMutationLease.acquire(stateDirectory: store.directory) })
    guard case .failed(let failure) = result else {
      Issue.record("expected cancellation")
      return
    }
    #expect(failure.nativeFailure == .cancelled)
    #expect(!failure.serverContactRequested && !failure.helperMutationRequested)
  }

  private func makeStore() throws -> UserProductSessionStateStore {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "native-state-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return UserProductSessionStateStore(directory: directory)
  }

  private func staleState(backend: PowerVPNBackend) -> UserProductSessionState {
    UserProductSessionState(
      sessionID: UUID().uuidString.lowercased(), target: "thu21",
      controlPath: "/tmp/native-synthetic.sock", phase: .failed, cleanupVerified: false,
      failure: "cleanup_unproven", backend: backend)
  }

  private func config(_ backend: PowerVPNBackend) throws -> PowerVPNTargetsConfiguration {
    try PowerVPNTargetsConfiguration.decode(
      Data(
        """
        {"portalOrigin":"https://192.0.2.1:4443","backend":"\(backend.rawValue)","targets":{"thu21":{"host":"192.0.2.21","user":"synthetic","resource":"Synthetic"}}}
        """.utf8))
  }

  private func deps(
    store: UserProductSessionStateStore, configured: PowerVPNBackend = .native,
    recover: @escaping @Sendable (PowerVPNTargetsConfiguration) async -> Bool = { _ in true }
  ) -> UserProductCommandDependencies {
    UserProductCommandDependencies(
      loadConfiguration: { try config(configured) },
      processRunner: NativeStoppedMaster(), stateStore: store,
      acquireMutationLease: { try ProductMutationLease.acquire(stateDirectory: store.directory) },
      nativeRecoverStale: recover)
  }
}

private struct NativeStoppedMaster: UserProductProcessRunning {
  func run(executable: String, arguments: [String], io: UserProductProcessIO)
    -> UserProductProcessResult
  {
    .init(started: true, exitCode: 255, output: "")
  }
}

private final class NativeFailedStartRunner: UserProductProcessRunning, @unchecked Sendable {
  let store: UserProductSessionStateStore
  let failure: String
  let cleaned: Bool
  private let lock = NSLock()
  private var count = 0
  var starts: Int { lock.withLock { count } }
  init(store: UserProductSessionStateStore, failure: String, cleaned: Bool = true) {
    self.store = store
    self.failure = failure
    self.cleaned = cleaned
  }
  func run(executable: String, arguments: [String], io: UserProductProcessIO)
    -> UserProductProcessResult
  {
    if arguments.first == "-G" {
      let socket = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".ssh/native-test-\(store.directory.lastPathComponent).sock").path
      return .init(
        started: true, exitCode: 0,
        output:
          "hostname 192.0.2.21\nuser synthetic\nport 22\ncontrolmaster auto\ncontrolpath \(socket)\n"
      )
    }
    if arguments.contains("-f") {
      lock.withLock { count += 1 }
      if let state = try? store.load() {
        _ = try? store.update(sessionID: state.sessionID) {
          $0.phase = .failed
          $0.cleanupVerified = cleaned
          $0.failure = failure
        }
      }
    }
    return .init(started: true, exitCode: 255, output: "")
  }
}
