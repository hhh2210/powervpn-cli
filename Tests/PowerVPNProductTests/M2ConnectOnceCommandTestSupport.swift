import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

let m2ValidArguments = [
  "m2", "connect-once", "--resource-display-name", " Campus NC ",
  "--ssh-target", "thu21", "--json",
]

func approval(trace: M2CommandTrace, response: M2TTYLineRead) -> M2TTYApproval {
  M2TTYApproval(exchange: { prompt in
    trace.capture(prompt: prompt)
    trace.record("approval")
    return response
  })
}

final class M2CommandTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedEvents: [String] = []
  private var storedPrompt: String?

  func record(_ event: String) { lock.withLock { storedEvents.append(event) } }
  func capture(prompt: String) { lock.withLock { storedPrompt = prompt } }
  var events: [String] { lock.withLock { storedEvents } }
  var prompt: String? { lock.withLock { storedPrompt } }
  func count(_ event: String) -> Int {
    lock.withLock { storedEvents.count { $0 == event } }
  }
}

final class M2ManualSignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  private let lock = NSLock()
  private let emitOnStart: Int
  private var handler: (@Sendable () -> Void)?
  private var starts = 0
  private var stops = 0

  init(emitOnStart: Int = 0) { self.emitOnStart = emitOnStart }
  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock {
      starts += 1
      self.handler = handler
    }
    emit(times: emitOnStart)
  }
  func stop() {
    lock.withLock {
      stops += 1
      handler = nil
    }
  }
  func emit(times: Int = 1) {
    for _ in 0..<times { lock.withLock { handler }?() }
  }
  var startCount: Int { lock.withLock { starts } }
  var stopCount: Int { lock.withLock { stops } }
}

final class M2CancellationRuntime: @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private var invocations = 0
  private var cancellations = 0

  func run(_ request: ProductM2ConnectRequest) async -> ProductM2ConnectReport {
    lock.withLock { invocations += 1 }
    started.signal()
    do { try await Task.sleep(for: .seconds(5)) } catch {
      lock.withLock { cancellations += 1 }
    }
    return report(outcome: .cancelled, mutated: true)
  }

  func waitUntilStarted() -> Bool { started.wait(timeout: .now() + 2) == .success }
  var invocationCount: Int { lock.withLock { invocations } }
  var cancellationCount: Int { lock.withLock { cancellations } }
}

func successReport(
  resource: String = "Campus NC",
  finalState: ProductM2ConnectionState = .disconnected
) -> ProductM2ConnectReport {
  report(
    outcome: .connectedAndCleanedUp, finalState: finalState,
    cleanup: true, mutated: true, resource: resource)
}

func report(
  outcome: ProductM2ConnectOutcome,
  finalState: ProductM2ConnectionState = .blocked,
  cleanup: Bool = true,
  mutated: Bool = false,
  resource: String = "Campus NC"
) -> ProductM2ConnectReport {
  ProductM2ConnectReport(
    outcome: outcome, finalState: finalState, lastGoodState: .ready,
    firstBadEvent: nil, resourceDisplayName: resource, sshTarget: .thu21,
    portalAcquisition: mutated ? .acquired : .notRequested,
    startOutcome: mutated ? .transportAcknowledged : .notAttempted,
    sshProof: .notAttempted, sshProofEvidence: nil,
    cleanupPath: mutated ? .sameLeaseStop : .notRequired,
    stopOutcome: mutated ? .transportAcknowledged : .notAttempted,
    emergencyStopOutcome: .notAttempted,
    portalLogout: mutated ? .accepted : .notRequired,
    cleanupEvidence: ProductM2CleanupEvidence(
      complete: cleanup, defaultRouteRestored: cleanup, dnsRestored: cleanup,
      interfacesRestored: cleanup, utunRestored: cleanup,
      surgeStateRestored: cleanup, helperGenerationRestored: cleanup),
    cleanupVerified: cleanup, serverContactRequested: mutated,
    helperMutationRequested: mutated)
}

func assertSortedJSON(_ json: String) {
  let keyLines = json.split(separator: "\n").compactMap { line -> String? in
    guard line.hasPrefix("  \"") else { return nil }
    let tail = line.dropFirst(3)
    guard let end = tail.firstIndex(of: "\"") else { return nil }
    return String(tail[..<end])
  }
  #expect(!keyLines.isEmpty)
  #expect(keyLines == keyLines.sorted())
}
