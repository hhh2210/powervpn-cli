import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct ProductHelperStatusProbeTests {
  @Test func passiveStatusNeverConstructsOrCallsAProbe() {
    let trace = ProductHelperProbeTrace(result: reachableResult())
    let runtime = makeRuntime(trace: trace)

    let report = runtime.helperStatus()

    #expect(report.directXPCStatus == .notProbed)
    #expect(!report.liveProbePerformed)
    #expect(trace.factoryCount == 0)
    #expect(trace.probeCount == 0)
    #expect(trace.timeouts.isEmpty)
  }

  @Test func explicitCLIProbeUsesFinalGenerationAndValueFreeProjection() async throws {
    let trace = ProductHelperProbeTrace(result: reachableResult())
    let result = try await runProductCommand(
      ["helper", "status", "--probe", "--json"],
      runtime: makeRuntime(trace: trace)
    )
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )
    let generation = try #require(object["generation"] as? [String: Any])

    #expect(result.exitCode == 0)
    #expect(object["directXPCStatus"] as? String == "current_reachable")
    #expect(object["liveProbePerformed"] as? Bool == true)
    #expect(object["preflightSafe"] as? Bool == true)
    #expect(generation["runs"] as? Int == 20)
    #expect(generation["pid"] == nil)
    #expect(trace.factoryCount == 1)
    #expect(trace.probeCount == 1)
    #expect(trace.timeouts == [2_000])
    #expect(!result.standardOutput.contains("transportAccepted"))
    #expect(!result.standardOutput.contains("helperGenerationRelation"))
    #expect(!result.standardOutput.contains("connectionCancelRequested"))
    #expect(!result.standardOutput.contains("synthetic-secret"))
  }

  @Test func preflightBlockTruthfullyReportsNoLiveProbe() async {
    let result = VendorXPCReachabilityResult(
      status: .preflightBlocked,
      probePerformed: false,
      transportAccepted: false,
      helperGenerationRelation: .inactive,
      finalGeneration: generation(runs: 19),
      connectionCancelRequested: false
    )
    let trace = ProductHelperProbeTrace(result: result)

    let report = await makeRuntime(trace: trace).helperStatusWithLiveProbe()

    #expect(report.productState == .blocked)
    #expect(report.directXPCStatus == .notProbed)
    #expect(!report.liveProbePerformed)
    #expect(!report.preflightSafe)
    #expect(!report.probeAvailable)
    #expect(report.blocker == .directXPCPreflightUnsafe)
    #expect(report.generation.runs == 19)
    #expect(trace.factoryCount == 1)
    #expect(trace.probeCount == 1)
  }

  @Test func attemptedTimeoutIsNotMisreportedAsNotProbed() async {
    let result = VendorXPCReachabilityResult(
      status: .timeout,
      probePerformed: true,
      transportAccepted: false,
      helperGenerationRelation: .launchedAndExited,
      finalGeneration: generation(runs: 20),
      connectionCancelRequested: true
    )
    let trace = ProductHelperProbeTrace(result: result)

    let report = await makeRuntime(trace: trace).helperStatusWithLiveProbe()

    #expect(report.productState == .blocked)
    #expect(report.directXPCStatus == .currentUnreachable)
    #expect(report.liveProbePerformed)
    #expect(report.preflightSafe)
    #expect(report.blocker == .directXPCUnreachable)
    #expect(report.generation.runs == 20)
  }

  private func makeRuntime(
    trace: ProductHelperProbeTrace
  ) -> ProductReadinessRuntime {
    ProductReadinessRuntime(
      observer: FixedProductObservation(observation()),
      helperProbeFactory: { trace.makeProbe() }
    )
  }

  private func observation() -> ProductReadinessObservation {
    ProductReadinessObservation(
      installedVersion: "3.2.1",
      installedBuild: "24572",
      installedArchitectures: ["x86_64"],
      officialGUIRunning: false,
      helperAvailable: true,
      generation: generation(runs: 19),
      directXPCStatus: .notProbed,
      directXPCPreflightSafe: true,
      profileSource: .operatorApprovedFixedOrigin,
      resourceSource: .unavailable,
      resourceCandidates: []
    )
  }

  private func reachableResult() -> VendorXPCReachabilityResult {
    VendorXPCReachabilityResult(
      status: .reachable,
      probePerformed: true,
      transportAccepted: true,
      helperGenerationRelation: .launchedAndExited,
      finalGeneration: generation(runs: 20),
      connectionCancelRequested: true
    )
  }

  private func generation(runs: Int) -> VendorHelperGenerationSnapshot {
    VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: false,
      inactiveConfirmed: true,
      activeCount: 0,
      pid: nil,
      runs: runs
    )
  }
}

private final class ProductHelperProbeTrace: @unchecked Sendable {
  private let lock = NSLock()
  private let result: VendorXPCReachabilityResult
  private var storedFactoryCount = 0
  private var storedProbeCount = 0
  private var storedTimeouts: [Int] = []

  init(result: VendorXPCReachabilityResult) {
    self.result = result
  }

  var factoryCount: Int { read { storedFactoryCount } }
  var probeCount: Int { read { storedProbeCount } }
  var timeouts: [Int] { read { storedTimeouts } }

  func makeProbe() -> any VendorXPCReachabilityProbing {
    lock.lock()
    storedFactoryCount += 1
    lock.unlock()
    return FixedProductHelperProbe(trace: self)
  }

  func perform(timeoutMilliseconds: Int) -> VendorXPCReachabilityResult {
    lock.lock()
    storedProbeCount += 1
    storedTimeouts.append(timeoutMilliseconds)
    lock.unlock()
    return result
  }

  private func read<Value>(_ body: () -> Value) -> Value {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

private struct FixedProductHelperProbe: VendorXPCReachabilityProbing {
  let trace: ProductHelperProbeTrace

  func probe(timeoutMilliseconds: Int) async -> VendorXPCReachabilityResult {
    trace.perform(timeoutMilliseconds: timeoutMilliseconds)
  }
}
