import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct ProxyAccessCommandTests {
  @Test func unavailableProviderStopsBeforeApprovalRuntimeAndChild() async throws {
    let trace = M2CommandTrace()
    let child = ProxyTestChildRunner()
    let result = try await runProxySSHCommand(
      Array(proxySSHArguments.dropLast()),
      authorizationAvailabilityFailure: { .providerUnavailable },
      generateApprovalCode: {
        trace.record("code")
        return "A1B2C3D4"
      },
      approval: M2TTYApproval(exchange: { _ in
        trace.record("approval")
        return .line("A1B2C3D4")
      }),
      childRunner: child,
      runtime: { _, _ in
        trace.record("runtime")
        return .failed(
          ProxyTunnelOpenFailure(
            failure: nil,
            helperMutationRequested: false,
            serverContactRequested: false,
            cleanupVerified: false
          ))
      }
    )

    #expect(result.exitCode == 69)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError == "runtime_unavailable\n")
    #expect(trace.events.isEmpty)
    #expect(child.invocationCount == 0)
  }

  @Test func nonInteractiveSkipsApprovalAndRouteDenialNeverSpawnsChild() async throws {
    let lease = ProxyTestLease(permitted: false)
    let child = ProxyTestChildRunner()
    let result = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: { throw TestFailure() },
      approval: M2TTYApproval(exchange: { _ in
        Issue.record("approval must be skipped")
        return .unavailable
      }),
      childRunner: child,
      runtime: proxyOpen(lease: lease)
    )

    #expect(result.exitCode == 70)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError == "target_not_covered\n")
    #expect(child.invocationCount == 0)
    #expect(lease.recordedEvents.last == "shutdown")
    #expect(!result.standardError.contains("Marker Resource"))
    #expect(!result.standardError.contains("11.11.30.21"))
  }

  @Test func sshUsesExactNCArgvAndPreservesChildExitAfterCleanup() async throws {
    let lease = ProxyTestLease()
    let child = ProxyTestChildRunner(outcome: .exited(23))
    let result = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: child,
      runtime: proxyOpen(lease: lease)
    )

    #expect(result.exitCode == 23)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError == "child_failed\n")
    #expect(
      child.specification
        == ProxyChildSpecification(
          executable: "/usr/bin/nc",
          arguments: ["11.11.30.21", "22"],
          standardInput: .inherited,
          standardOutput: .inherited
        ))
    #expect(child.readiness == ProxyChildReadiness.none)
    #expect(lease.recordedEvents.last == "shutdown")
  }

  @Test func cleanupUnprovenOverridesChildAndCancellationResults() async throws {
    for outcome in [ProxyChildRunOutcome.exited(19), .cancelled] {
      let lease = ProxyTestLease(cleanupVerified: false)
      let result = try await runProxySSHCommand(
        proxySSHArguments,
        authorizationAvailabilityFailure: { nil },
        childRunner: ProxyTestChildRunner(outcome: outcome),
        runtime: proxyOpen(lease: lease)
      )
      #expect(result.exitCode == 74)
      #expect(result.standardOutput.isEmpty)
      #expect(result.standardError == "cleanup_unproven\n")
    }
  }

  @Test func truthfulOpenFailureIncludesClosedFailureDiagnostics() async throws {
    let generationFence = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      runtime: proxyFailedOpen(
        mutated: false,
        cleanupVerified: false,
        failure: .generationFenceRejected,
        firstBadEvent: .generationFenceRejected
      )
    )
    #expect(generationFence.exitCode == 69)
    #expect(
      generationFence.standardError
        == "tunnel_open_failed:generation_fence_rejected:first_bad=generation_fence_rejected\n")

    let routeActivation = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      runtime: proxyFailedOpen(
        mutated: true,
        cleanupVerified: true,
        failure: .routeActivationRejected,
        firstBadEvent: .routeActivationRejected
      )
    )
    #expect(routeActivation.exitCode == 70)
    #expect(
      routeActivation.standardError
        == "tunnel_open_failed:route_activation_rejected:first_bad=route_activation_rejected\n")

    let uncleanMutation = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      runtime: proxyFailedOpen(mutated: true, cleanupVerified: false)
    )
    #expect(uncleanMutation.exitCode == 74)
    #expect(uncleanMutation.standardError == "cleanup_unproven\n")
  }

  @Test func catalogMappingFailureIncludesClosedCatalogDiagnostics() async throws {
    let sentinel = "server-catalog-value-must-not-escape"
    let xml = m2ResourceXML(["server-display-must-not-escape"])
      .replacingOccurrences(of: "port=\"500\"", with: "port=\"\(sentinel)\"")
    let fixture = try authenticatedSnapshot(resourceXML: xml)
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: ProductM2TestTrace()
      )
    )
    let child = ProxyTestChildRunner()

    let result = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: child,
      runtime: { request, budget in
        await openProductProxyTunnel(runtime: runtime, request: request, budget: budget)
      }
    )

    #expect(result.exitCode == 69)
    #expect(
      result.standardError
        == "tunnel_open_failed:resource_catalog_rejected"
        + ":first_bad=resource_catalog_rejected"
        + ":selection=catalog_mapping"
        + ":catalog=resource.integer_invalid"
        + ":ordinal=1:field_path=common.ike_port\n")
    #expect(!result.standardError.contains(sentinel))
    #expect(!result.standardError.contains("server-display-must-not-escape"))
    #expect(child.invocationCount == 0)
  }

  @Test func emptyCatalogHasSelectionTokenWithoutMappingDetails() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML([]))
    defer { fixture.erase() }
    let runtime = ProductPersistentTunnelRuntime(
      dependencies: productM2TestDependencies(
        snapshot: fixture.snapshot,
        trace: ProductM2TestTrace()
      )
    )
    let child = ProxyTestChildRunner()

    let result = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: child,
      runtime: { request, budget in
        await openProductProxyTunnel(runtime: runtime, request: request, budget: budget)
      }
    )

    #expect(result.exitCode == 69)
    #expect(
      result.standardError
        == "tunnel_open_failed:resource_catalog_rejected"
        + ":first_bad=resource_catalog_rejected"
        + ":selection=catalog_empty\n")
    #expect(child.invocationCount == 0)
  }

  @Test func earlySignalNeverOpensRuntimeOrSpawnsChild() async throws {
    let monitor = M2ManualSignalMonitor(emitOnStart: 2)
    let trace = M2CommandTrace()
    let child = ProxyTestChildRunner()
    let result = try await runProxySSHCommand(
      proxySSHArguments,
      authorizationAvailabilityFailure: { nil },
      signalMonitorFactory: { monitor },
      childRunner: child,
      runtime: { _, _ in
        trace.record("runtime")
        return .failed(
          ProxyTunnelOpenFailure(
            failure: nil,
            helperMutationRequested: false,
            serverContactRequested: false,
            cleanupVerified: false
          ))
      }
    )

    #expect(result.exitCode == 130)
    #expect(trace.events.isEmpty)
    #expect(child.invocationCount == 0)
    #expect(monitor.stopCount == 1)
  }
  @Test func cancellationDuringOpenUsesTypedFailurePrecedenceAndSpawnsNoNC() async throws {
    let scenarios: [(ProductM2ConnectOutcome, Bool, Int32, String)] = [
      (.cancelled, true, 130, "cancelled"),
      (.cleanupUnproven, false, 74, "cleanup_unproven"),
    ]
    for (failure, cleanupVerified, exitCode, token) in scenarios {
      let monitor = M2ManualSignalMonitor()
      let child = ProxyTestChildRunner()
      let runtime = ProxyCancellationOpenRuntime(
        failure: ProxyTunnelOpenFailure(
          failure: failure,
          helperMutationRequested: false,
          serverContactRequested: false,
          cleanupVerified: cleanupVerified
        ))
      let command = Task {
        try await runProxySSHCommand(
          proxySSHArguments,
          authorizationAvailabilityFailure: { nil },
          signalMonitorFactory: { monitor },
          childRunner: child,
          runtime: runtime.open
        )
      }
      #expect(runtime.waitUntilStarted())
      monitor.emit()
      let result = try await command.value

      #expect(result.exitCode == exitCode)
      #expect(result.standardOutput.isEmpty)
      #expect(result.standardError == "\(token)\n")
      #expect(!result.standardError.contains("Marker Resource"))
      #expect(!result.standardError.contains("11.11.30.21"))
      #expect(child.invocationCount == 0)
      #expect(monitor.stopCount == 1)
    }
  }

  @Test func activeSignalCancelsChildThenAwaitsVerifiedShutdown() async throws {
    let monitor = M2ManualSignalMonitor()
    let lease = ProxyTestLease()
    let child = ProxyTestChildRunner(waitForCancellation: true)
    let command = Task {
      try await runProxySSHCommand(
        proxySSHArguments,
        authorizationAvailabilityFailure: { nil },
        signalMonitorFactory: { monitor },
        childRunner: child,
        runtime: proxyOpen(lease: lease)
      )
    }
    #expect(child.waitUntilStarted())
    monitor.emit(times: 2)
    let result = try await command.value

    #expect(result.exitCode == 130)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError == "cancelled\n")
    #expect(lease.recordedEvents.last == "shutdown")
    #expect(monitor.stopCount == 1)
  }

  @Test func proxyProcessWaitsForPostStopDrainBeforeReturningCancellation() async throws {
    let monitor = M2ManualSignalMonitor()
    let completion = M2CommandTrace()
    let lease = ProxyTestLease(blocksPostStopDrain: true)
    let command = Task {
      let result = try await runProxySSHCommand(
        proxySSHArguments,
        authorizationAvailabilityFailure: { nil },
        signalMonitorFactory: { monitor },
        childRunner: ProxyTestChildRunner(outcome: .exited(0)),
        runtime: proxyOpen(lease: lease)
      )
      completion.record("returned")
      return result
    }
    #expect(lease.waitUntilShutdownStarted())
    monitor.emit()
    await Task.yield()
    #expect(completion.events.isEmpty)
    await lease.releaseShutdown()
    let result = try await command.value

    #expect(result.exitCode == 130)
    #expect(result.standardError == "cancelled\n")
    #expect(completion.events == ["returned"])
    #expect(monitor.stopCount == 1)
  }

  @Test func interactiveApprovalPrecedesRuntimeAndDenialStopsIt() async throws {
    let acceptedTrace = M2CommandTrace()
    let interactiveArguments = Array(proxySSHArguments.dropLast())
    let accepted = try await runProxySSHCommand(
      interactiveArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: {
        acceptedTrace.record("code")
        return "A1B2C3D4"
      },
      approval: M2TTYApproval(exchange: { _ in
        acceptedTrace.record("approval")
        return .line("A1B2C3D4")
      }),
      runtime: { _, _ in
        acceptedTrace.record("runtime")
        return .failed(
          ProxyTunnelOpenFailure(
            failure: nil,
            helperMutationRequested: false,
            serverContactRequested: false,
            cleanupVerified: false
          ))
      }
    )
    #expect(accepted.exitCode == 69)
    #expect(acceptedTrace.events == ["code", "approval", "runtime"])

    let deniedTrace = M2CommandTrace()
    let denied = try await runProxySSHCommand(
      interactiveArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: {
        deniedTrace.record("code")
        return "A1B2C3D4"
      },
      approval: M2TTYApproval(exchange: { _ in
        deniedTrace.record("approval")
        return .line("wrong")
      }),
      runtime: { _, _ in
        deniedTrace.record("runtime")
        return .failed(
          ProxyTunnelOpenFailure(
            failure: nil,
            helperMutationRequested: false,
            serverContactRequested: false,
            cleanupVerified: false
          ))
      }
    )
    #expect(denied.exitCode == 77)
    #expect(denied.standardError == "approval_denied\n")
    #expect(deniedTrace.events == ["code", "approval"])
  }

  private struct TestFailure: Error {}
}
