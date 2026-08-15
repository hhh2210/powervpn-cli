import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct ProxyServeCommandTests {
  @Test func serveUsesExactOpenSSHArgvAndEmitsOneTerminalTargetFreeJSON() async throws {
    let lease = ProxyTestLease()
    let child = ProxyTestChildRunner()
    let readiness = M2CommandTrace()
    let result = try await runProxyServeCommand(
      proxyServeArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: child,
      emitReadiness: { readiness.record("ready") },
      runtime: proxyOpen(lease: lease)
    )

    #expect(result.exitCode == 0)
    #expect(result.standardError.isEmpty)
    #expect(readiness.events == ["ready"])
    #expect(
      child.specification
        == ProxyChildSpecification(
          executable: "/usr/bin/ssh",
          arguments: [
            "-N", "-T", "-D", "127.0.0.1:2345",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "BatchMode=yes",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ConnectTimeout=10",
            "thu52",
          ],
          standardInput: .null,
          standardOutput: .null
        ))
    #expect(child.readiness == .loopback(port: 2345, timeoutMilliseconds: 10_000))
    #expect(result.standardOutput.split(separator: "\n").count == 1)
    #expect(!result.standardOutput.contains("Marker Resource"))
    #expect(!result.standardOutput.contains("thu52"))
    #expect(!result.standardOutput.contains("2345"))
    #expect(!result.standardOutput.contains("127.0.0.1"))
    #expect(result.standardOutput.contains("\"outcome\":\"child_exited\""))
    #expect(result.standardOutput.contains("\"cleanupVerified\":true"))
    #expect(lease.recordedEvents == ["shutdown"])
  }

  @Test func humanModeWritesNoStdoutAndReportsReadinessOnlyThroughEmitter() async throws {
    let arguments = Array(proxyServeArguments.dropLast())
    let readiness = M2CommandTrace()
    let result = try await runProxyServeCommand(
      arguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: ProxyTestChildRunner(),
      emitReadiness: { readiness.record("ready") },
      runtime: proxyOpen(lease: ProxyTestLease())
    )

    #expect(result.exitCode == 0)
    #expect(result.standardOutput.isEmpty)
    #expect(result.standardError.isEmpty)
    #expect(readiness.events == ["ready"])
  }

  @Test func readinessFailureIsTargetFreeAndCleanupPrecedenceWins() async throws {
    let readyFailure = try await runProxyServeCommand(
      proxyServeArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: ProxyTestChildRunner(outcome: .readinessFailed),
      emitReadiness: { Issue.record("not ready") },
      runtime: proxyOpen(lease: ProxyTestLease())
    )
    #expect(readyFailure.exitCode == 70)
    #expect(readyFailure.standardError == "forward_not_ready\n")
    #expect(readyFailure.standardOutput.contains("\"outcome\":\"forward_not_ready\""))
    assertTargetFree(readyFailure)

    let cleanupFailure = try await runProxyServeCommand(
      proxyServeArguments,
      authorizationAvailabilityFailure: { nil },
      childRunner: ProxyTestChildRunner(outcome: .readinessFailed),
      emitReadiness: {},
      runtime: proxyOpen(lease: ProxyTestLease(cleanupVerified: false))
    )
    #expect(cleanupFailure.exitCode == 74)
    #expect(cleanupFailure.standardError == "cleanup_unproven\n")
    #expect(cleanupFailure.standardOutput.contains("\"outcome\":\"cleanup_unproven\""))
    assertTargetFree(cleanupFailure)
  }
  @Test func cancellationDuringOpenUsesTypedFailurePrecedenceAndTargetFreeJSON() async throws {
    let scenarios: [(ProductM2ConnectOutcome, Bool, Int32, String)] = [
      (.cancelled, true, 130, "cancelled"),
      (.cleanupUnproven, false, 74, "cleanup_unproven"),
    ]
    for (failure, cleanupVerified, exitCode, token) in scenarios {
      let monitor = M2ManualSignalMonitor()
      let child = ProxyTestChildRunner()
      let readiness = M2CommandTrace()
      let runtime = ProxyCancellationOpenRuntime(
        failure: ProxyTunnelOpenFailure(
          failure: failure,
          helperMutationRequested: false,
          serverContactRequested: false,
          cleanupVerified: cleanupVerified
        ))
      let command = Task {
        try await runProxyServeCommand(
          proxyServeArguments,
          authorizationAvailabilityFailure: { nil },
          signalMonitorFactory: { monitor },
          childRunner: child,
          emitReadiness: { readiness.record("ready") },
          runtime: runtime.open
        )
      }
      #expect(runtime.waitUntilStarted())
      monitor.emit()
      let result = try await command.value

      #expect(result.exitCode == exitCode)
      #expect(result.standardError == "\(token)\n")
      #expect(result.standardOutput.contains("\"outcome\":\"\(token)\""))
      #expect(result.standardOutput.contains("\"runtimeInvoked\":true"))
      #expect(result.standardOutput.contains("\"helperMutationRequested\":false"))
      #expect(
        result.standardOutput.contains(
          "\"cleanupVerified\":\(cleanupVerified ? "true" : "false")"
        ))
      #expect(child.invocationCount == 0)
      #expect(readiness.events.isEmpty)
      #expect(monitor.stopCount == 1)
      assertTargetFree(result)
    }
  }

  @Test func serveProviderFailureJSONIsClosedAndDoesNotRequestApproval() async throws {
    let trace = M2CommandTrace()
    let result = try await runProxyServeCommand(
      proxyServeArguments,
      authorizationAvailabilityFailure: { .providerUnavailable },
      generateApprovalCode: {
        trace.record("approval")
        return "A1B2C3D4"
      },
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
    #expect(result.standardError == "runtime_unavailable\n")
    #expect(result.standardOutput.contains("\"runtimeInvoked\":false"))
    #expect(trace.events.isEmpty)
    assertTargetFree(result)
  }

  private func assertTargetFree(_ result: ProxyCommandResult) {
    for sentinel in ["Marker Resource", "thu52", "2345", "127.0.0.1"] {
      #expect(!result.standardOutput.contains(sentinel))
      #expect(!result.standardError.contains(sentinel))
    }
  }
}
