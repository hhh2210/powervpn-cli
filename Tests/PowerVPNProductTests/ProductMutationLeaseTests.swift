import Foundation
import Testing

@testable import PowerVPNPortal

@testable import PowerVPNProduct

@Suite struct ProductMutationLeaseTests {
  @Test func independentContenderFailsAndLockInodeIsRetained() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("powervpn-mutation-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    var first: ProductMutationLease? = try ProductMutationLease.acquire(stateDirectory: root)
    #expect(first != nil)
    #expect(throws: ProductMutationLeaseError.alreadyHeld) {
      try ProductMutationLease.acquire(stateDirectory: root)
    }

    let lock = root.appendingPathComponent("mutation.lock")
    #expect(FileManager.default.fileExists(atPath: lock.path))
    #expect(try permissions(root) == 0o700)
    #expect(try permissions(lock) == 0o600)

    first = nil
    #expect(FileManager.default.fileExists(atPath: lock.path))
    let next = try ProductMutationLease.acquire(stateDirectory: root)
    withExtendedLifetime(next) {}
  }

  @Test func coordinatorLosesBeforeAuthorizationOrHelperAccess() async throws {
    let trace = ProductM2TestTrace()
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    var dependencies = productM2TestDependencies(snapshot: fixture.snapshot, trace: trace)
    dependencies = ProductM2ConnectOnceDependencies(
      acquireMutationLease: { throw ProductMutationLeaseError.alreadyHeld },
      controlRuntimePreflightAccepted: dependencies.controlRuntimePreflightAccepted,
      observeGeneration: dependencies.observeGeneration,
      preflightAccepted: dependencies.preflightAccepted,
      captureNetworkBaseline: dependencies.captureNetworkBaseline,
      baselineStable: dependencies.baselineStable,
      assessActiveConnection: dependencies.assessActiveConnection,
      authorizationSource: dependencies.authorizationSource,
      authorizationAvailabilityFailure: dependencies.authorizationAvailabilityFailure,
      beginAuthorization: dependencies.beginAuthorization,
      control: dependencies.control,
      proveFreshSSH: dependencies.proveFreshSSH,
      verifyCleanup: dependencies.verifyCleanup
    )

    let report = await ProductM2ConnectOnceCoordinator(dependencies: dependencies).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21),
      budget: m2TestBudget()
    )

    #expect(report.outcome == .preflightBlocked)
    #expect(trace.count("session_preflight") == 1)
    #expect(trace.count("observe_generation") == 0)
    #expect(trace.count("acquire") == 0)
    #expect(trace.count("begin_start") == 0)
  }
}

private func permissions(_ url: URL) throws -> Int {
  let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
  return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
}
