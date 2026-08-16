import Foundation

@testable import PowerVPNCLI
@testable import PowerVPNProduct

let proxySSHArguments = [
  "proxy", "ssh", "--resource-display-name", "Marker Resource",
  "--ssh-target", "thu21", "192.0.2.21", "22", "--non-interactive",
]

let proxyServeArguments = [
  "proxy", "serve", "--resource-display-name", "Marker Resource",
  "--ssh-target", "thu52", "--listen-port", "2345", "--non-interactive", "--json",
]

final class ProxyTestLease: ProxyTunnelLeasing, @unchecked Sendable {
  private let lock = NSLock()
  private let permitted: Bool
  private let verified: Bool
  private let blocksPostStopDrain: Bool
  private let shutdownStarted = DispatchSemaphore(value: 0)
  private let shutdownGate = ProxyTestShutdownGate()
  private var events: [String] = []

  init(
    permitted: Bool = true,
    cleanupVerified: Bool = true,
    blocksPostStopDrain: Bool = false
  ) {
    self.permitted = permitted
    verified = cleanupVerified
    self.blocksPostStopDrain = blocksPostStopDrain
  }

  func permitsIPv4(_ address: UInt32) async -> Bool {
    lock.withLock { events.append("permit:\(address)") }
    return permitted
  }

  func shutdown(budget _: ProductM2CleanupBudget) async -> ProxyTunnelShutdown {
    lock.withLock { events.append("shutdown") }
    shutdownStarted.signal()
    if blocksPostStopDrain {
      await shutdownGate.wait()
    }
    return ProxyTunnelShutdown(cleanupVerified: verified)
  }

  var recordedEvents: [String] { lock.withLock { events } }
  func waitUntilShutdownStarted() -> Bool {
    shutdownStarted.wait(timeout: .now() + 2) == .success
  }

  func releaseShutdown() async {
    await shutdownGate.release()
  }
}
private actor ProxyTestShutdownGate {
  private var released = false
  private var continuation: CheckedContinuation<Void, Never>?

  func wait() async {
    guard !released else { return }
    await withCheckedContinuation { continuation = $0 }
  }

  func release() {
    released = true
    continuation?.resume()
    continuation = nil
  }
}

final class ProxyTestChildRunner: ProxyChildRunning, @unchecked Sendable {
  private let lock = NSLock()
  private let configuredOutcome: ProxyChildRunOutcome
  private let waitForCancellation: Bool
  private let started = DispatchSemaphore(value: 0)
  private var specifications: [ProxyChildSpecification] = []
  private var readinessValues: [ProxyChildReadiness] = []

  init(
    outcome: ProxyChildRunOutcome = .exited(0),
    waitForCancellation: Bool = false
  ) {
    configuredOutcome = outcome
    self.waitForCancellation = waitForCancellation
  }

  func run(
    _ specification: ProxyChildSpecification,
    readiness: ProxyChildReadiness,
    onReady: @escaping @Sendable () -> Void
  ) async -> ProxyChildRunResult {
    lock.withLock {
      specifications.append(specification)
      readinessValues.append(readiness)
    }
    started.signal()
    if waitForCancellation {
      do {
        try await Task.sleep(for: .seconds(10))
      } catch {
        return ProxyChildRunResult(outcome: .cancelled, becameReady: false)
      }
    }
    let becameReady: Bool
    if case .loopback = readiness, configuredOutcome == .exited(0) {
      becameReady = true
      onReady()
    } else {
      becameReady = false
    }
    return ProxyChildRunResult(outcome: configuredOutcome, becameReady: becameReady)
  }

  func waitUntilStarted() -> Bool {
    started.wait(timeout: .now() + 2) == .success
  }

  var invocationCount: Int { lock.withLock { specifications.count } }
  var specification: ProxyChildSpecification? { lock.withLock { specifications.last } }
  var readiness: ProxyChildReadiness? { lock.withLock { readinessValues.last } }
}
final class ProxyCancellationOpenRuntime: @unchecked Sendable {
  private let started = DispatchSemaphore(value: 0)
  private let failure: ProxyTunnelOpenFailure

  init(failure: ProxyTunnelOpenFailure) {
    self.failure = failure
  }

  func open(
    request _: ProductM2ConnectRequest,
    budget _: ProductM2AbsoluteBudget
  ) async -> ProxyTunnelOpenResult {
    started.signal()
    try? await Task.sleep(for: .seconds(10))
    return .failed(failure)
  }

  func waitUntilStarted() -> Bool {
    started.wait(timeout: .now() + 2) == .success
  }
}

func proxyOpen(
  lease: ProxyTestLease,
  helperMutationRequested: Bool = true,
  serverContactRequested: Bool = true
) -> ProxyTunnelOpenOperation {
  { _, _ in
    .opened(
      lease,
      helperMutationRequested: helperMutationRequested,
      serverContactRequested: serverContactRequested
    )
  }
}

func proxyFailedOpen(
  mutated: Bool,
  contacted: Bool = false,
  cleanupVerified: Bool,
  failure: ProductM2ConnectOutcome? = nil,
  firstBadEvent: ProductM2BadEvent? = nil
) -> ProxyTunnelOpenOperation {
  { _, _ in
    .failed(
      ProxyTunnelOpenFailure(
        failure: failure,
        firstBadEvent: firstBadEvent,
        helperMutationRequested: mutated,
        serverContactRequested: contacted,
        cleanupVerified: cleanupVerified
      ))
  }
}
