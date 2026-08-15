import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductPersistentTunnelTests {
  @Test func openErasesStartMaterialAndConcurrentShutdownJoinsOneCleanup() async throws {
    let trace = ProductM2TestTrace()
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    )

    let result = await runtime.open(
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      startupBudget: m2TestBudget()
    )
    guard case .opened(let lease, let openReport) = result else {
      Issue.record("persistent tunnel did not open")
      return
    }

    #expect(openReport.opened)
    #expect(openReport.helperMutationRequested)
    #expect(openReport.serverContactRequested)
    #expect(openReport.authorizationClose == .notRequired)
    #expect(openReport.authorizationOwnedMaterialErased)
    #expect(trace.count("logout") == 0)
    #expect(trace.count("erase_authorization") == 1)
    #expect(trace.count("ssh") == 0)
    let encodedOpenReport = try #require(
      String(bytes: try JSONEncoder().encode(openReport), encoding: .utf8)
    )
    #expect(!encodedOpenReport.contains("Campus NC"))
    #expect(!encodedOpenReport.contains("thu21"))
    let targetPermitted = await lease.permitsIPv4(ipv4(11, 11, 30, 21))
    let unrelatedPermitted = await lease.permitsIPv4(ipv4(203, 0, 113, 1))
    #expect(targetPermitted)
    #expect(!unrelatedPermitted)

    async let first = lease.shutdown(budget: .start())
    async let second = lease.shutdown(budget: .start())
    let reports = await [first, second]

    #expect(reports[0] == reports[1])
    #expect(reports[0].disconnected)
    #expect(reports[0].cleanupPath == .sameLeaseStop)
    #expect(trace.count("stop") == 1)
    #expect(trace.count("logout") == 1)
    #expect(trace.count("verify") == 1)
    let targetPermittedAfterShutdown = await lease.permitsIPv4(ipv4(11, 11, 30, 21))
    #expect(!targetPermittedAfterShutdown)
  }
  @Test func activeRuntimeRejectsSecondOpenWithoutClaimingSideEffects() async throws {
    let trace = ProductM2TestTrace()
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    )
    let first = await runtime.open(
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      startupBudget: m2TestBudget()
    )
    guard case .opened(let lease, _) = first else {
      Issue.record("persistent tunnel did not open")
      return
    }
    let duplicate = await runtime.open(
      request: ProductM2ConnectRequest(resourceDisplayName: "Other", sshTarget: .thu52),
      startupBudget: m2TestBudget()
    )
    guard case .failed(let report) = duplicate else {
      Issue.record("active runtime accepted a second open")
      return
    }
    #expect(!report.helperMutationRequested)
    #expect(!report.serverContactRequested)
    #expect((await lease.shutdown(budget: .start())).cleanupVerified)
  }

  @Test func cleanupFailureNeverReportsDisconnected() async throws {
    let trace = ProductM2TestTrace()
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        cleanup: .unavailable
      )
    )
    let result = await runtime.open(
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      startupBudget: m2TestBudget()
    )
    guard case .opened(let lease, _) = result else {
      Issue.record("persistent tunnel did not open")
      return
    }

    let report = await lease.shutdown(budget: .start())
    #expect(!report.cleanupVerified)
    #expect(report.cleanupPath == .cleanupUnproven)
    #expect(!report.disconnected)
  }

  @Test func startupFailureReturnsNoLeaseAndValueFreeReport() async throws {
    let trace = ProductM2TestTrace()
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .preSubmissionFailure
      )
    )

    let result = await runtime.open(
      request: ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      startupBudget: m2TestBudget()
    )
    guard case .failed(let report) = result else {
      Issue.record("failed start returned a live lease")
      return
    }
    #expect(report.outcome == .rejected)
    #expect(report.failure == .startRejected)
    #expect(report.state == .stopped)
    #expect(!report.opened)
    #expect(!report.helperMutationRequested)
    #expect(report.serverContactRequested)
  }
  @Test func proxyAdapterPreservesTypedPersistentOpenFailure() async throws {
    let trace = ProductM2TestTrace()
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: trace,
        plan: .preSubmissionFailure
      )
    )

    let result = await openProductProxyTunnel(
      runtime: runtime,
      request: ProductM2ConnectRequest(
        resourceDisplayName: "Campus NC",
        sshTarget: .thu21
      ),
      budget: m2TestBudget()
    )
    guard case .failed(let failure) = result else {
      Issue.record("proxy adapter accepted a failed persistent open")
      return
    }
    #expect(failure.failure == .startRejected)
    #expect(!failure.helperMutationRequested)
    #expect(failure.serverContactRequested)
  }

}

private func ipv4(
  _ first: UInt32,
  _ second: UInt32,
  _ third: UInt32,
  _ fourth: UInt32
) -> UInt32 {
  (first << 24) | (second << 16) | (third << 8) | fourth
}
