import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite(.serialized)
struct PortalDryRunCommandTests {
  @Test func exactArgumentsProduceRequest() throws {
    let request = try parsePortalDryRunArguments(validArguments())

    #expect(request.resourceDisplayName == "login21")
    #expect(request.sshTarget == .thu21)
  }

  @Test func alteredCommandShapesFailClosed() {
    let invalid = [
      Array(validArguments().dropLast()),
      ["portal", "dry-run", "--resource", "login21", "--ssh-target", "thu21", "--json"],
      [
        "portal", "dry-run", "--resource-display-name", "login21", "--ssh-target", "thu21",
        "--verbose",
      ],
      [
        "portal", "dry-run", "--resource-display-name", "login21\nother", "--ssh-target", "thu21",
        "--json",
      ],
    ]

    for arguments in invalid {
      #expect(throws: PortalDryRunCommandError.invalidArguments) {
        try parsePortalDryRunArguments(arguments)
      }
    }
  }

  @Test func acceptedReportEmitsOnlyValueFreeContract() async throws {
    let report = dryRunReport(outcome: .accepted)
    let result = try await runPortalDryRunCommand(
      validArguments(),
      runtime: { _ in report },
      signalMonitorFactory: { InertPortalDryRunSignalMonitor() }
    )

    #expect(result.exitCode == 0)
    let data = try #require(result.standardOutput.data(using: .utf8))
    let object = try #require(
      JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
    #expect(
      Set(object.keys) == [
        "candidateCount", "containsSecrets", "dryRunAccepted",
        "helperMutationRequested", "logoutOutcome", "m2CoordinatorRequested",
        "matchingCandidateCount", "operations", "outcome", "ownedMaterialErased",
        "schemaVersion", "selectedCandidateCount", "sshRequested",
        "portalAcquisitionStatus",
        "startSnapshotComplete", "targetRouteCovered",
      ])
    #expect(object["schemaVersion"] as? Int == 2)
    #expect(object["portalAcquisitionStatus"] as? String == "accepted")
    let operations = try #require(object["operations"] as? [String: Any])
    #expect(
      Set(operations.keys) == [
        "loginAccepted", "loginRequested", "logoutAccepted", "logoutAttempted",
        "portalAcquisitionRequested", "resourceListAccepted", "resourceListRequested",
        "sessionCheckAccepted", "sessionCheckRequested", "startSnapshotConstructed",
        "startSnapshotValidationRequested", "targetRouteValidationRequested",
      ])
    #expect(!result.standardOutput.contains("login21"))
    #expect(!result.standardOutput.contains("thu21"))
    #expect(!result.standardOutput.contains("cookie"))
    #expect(!result.standardOutput.contains("psk"))
  }

  @Test func rejectedReportReturnsUnavailableExit() async throws {
    let report = dryRunReport(outcome: .resourceNotFound)
    let result = try await runPortalDryRunCommand(
      validArguments(),
      runtime: { _ in report },
      signalMonitorFactory: { InertPortalDryRunSignalMonitor() }
    )

    #expect(result.exitCode == 69)
    #expect(result.standardOutput.contains("\"dryRunAccepted\":false"))
    #expect(result.standardOutput.contains("\"outcome\":\"resource_not_found\""))
  }

  @Test func signalCancelsInstalledRuntimeTask() async throws {
    let observation = PortalDryRunCancellationObservation()
    let report = dryRunReport(outcome: .cancelled)
    let result = try await runPortalDryRunCommand(
      validArguments(),
      runtime: { _ in
        observation.recordInvocation(cancelled: Task.isCancelled)
        return report
      },
      signalMonitorFactory: { ImmediatePortalDryRunSignalMonitor() }
    )

    #expect(result.exitCode == 130)
    #expect(observation.invocationCount == 1)
    #expect(observation.observedCancellation)
  }

  private func validArguments() -> [String] {
    [
      "portal", "dry-run", "--resource-display-name", "login21",
      "--ssh-target", "thu21", "--json",
    ]
  }
}

private func dryRunReport(
  outcome: ProductPortalDryRunOutcome
) -> ProductPortalDryRunReport {
  let accepted = outcome == .accepted
  return ProductPortalDryRunReport(
    outcome: outcome,
    portalAcquisitionStatus: .accepted,
    operations: ProductPortalDryRunOperations(
      portalAcquisitionRequested: true,
      loginRequested: true,
      loginAccepted: true,
      resourceListRequested: true,
      resourceListAccepted: true,
      sessionCheckRequested: false,
      sessionCheckAccepted: false,
      startSnapshotValidationRequested: true,
      startSnapshotConstructed: accepted,
      targetRouteValidationRequested: accepted,
      logoutAttempted: true,
      logoutAccepted: true
    ),
    candidateCount: 1,
    matchingCandidateCount: accepted ? 1 : 0,
    selectedCandidateCount: accepted ? 1 : 0,
    startSnapshotComplete: accepted,
    targetRouteCovered: accepted,
    logoutOutcome: .accepted,
    ownedMaterialErased: true
  )
}

private final class InertPortalDryRunSignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  func start(handler _: @escaping @Sendable () -> Void) {}
  func stop() {}
}

private final class ImmediatePortalDryRunSignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  func start(handler: @escaping @Sendable () -> Void) { handler() }
  func stop() {}
}

private final class PortalDryRunCancellationObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var invocations = 0
  private var cancellationObserved = false

  func recordInvocation(cancelled: Bool) {
    lock.withLock {
      invocations += 1
      cancellationObserved = cancelled
    }
  }

  var invocationCount: Int { lock.withLock { invocations } }
  var observedCancellation: Bool { lock.withLock { cancellationObserved } }
}
