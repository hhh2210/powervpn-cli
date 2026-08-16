import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct M2ConnectOnceCommandTests {
  private let validArguments = [
    "m2", "connect-once", "--resource-display-name", " Campus NC ",
    "--ssh-target", "thu21", "--json",
  ]

  @Test func exactGrammarPreservesDisplayNameWithoutNormalization() throws {
    let request = try parseM2ConnectOnceArguments(validArguments)
    #expect(request.resourceDisplayName == " Campus NC ")
    #expect(request.sshTarget == .thu21)
    #expect(
      try parseM2ConnectOnceArguments(arguments(name: "Campus", target: "thu52"))
        .sshTarget == .thu52)

    let boundary = String(repeating: "é", count: 128)
    #expect(
      try parseM2ConnectOnceArguments(arguments(name: boundary)).resourceDisplayName == boundary)
  }

  @Test func malformedGrammarAndPromptUnsafeNamesFailBeforeApprovalOrRuntime() async {
    let invalid = [
      [] as [String],
      ["m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21"],
      arguments(name: ""),
      arguments(name: "Campus\nNC"),
      arguments(name: "Campus\u{2028}NC"),
      arguments(name: "Campus\u{2029}NC"),
      arguments(name: "Campus\u{0000}NC"),
      arguments(name: String(repeating: "é", count: 129)),
      arguments(name: "Campus", target: "THU21"),
      arguments(name: "Campus") + ["--yes"],
      arguments(name: "Campus") + ["--resource-display-name", "Campus"],
      [
        "m2", "connect-once", "--ssh-target", "thu21", "--resource-display-name", "Campus",
        "--json",
      ],
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21",
        "--stdin",
      ],
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21", "--env",
      ],
    ]
    for candidate in invalid {
      let trace = M2CommandTrace()
      do {
        _ = try await runM2ConnectOnceCommand(
          candidate,
          authorizationAvailabilityFailure: { nil },
          generateApprovalCode: {
            trace.record("code")
            return "A1B2C3D4"
          },
          approval: approval(trace: trace, response: .line("A1B2C3D4")),
          signalMonitorFactory: {
            trace.record("monitor")
            return M2ManualSignalMonitor()
          },
          runtime: { _, _ in
            trace.record("runtime")
            return successReport()
          }
        )
        Issue.record("expected usage rejection")
      } catch let error as M2ConnectOnceCommandError {
        #expect(error == .invalidArguments)
        #expect(error.description.hasPrefix("usage: powervpn m2 connect-once"))
      } catch {
        Issue.record("unexpected error: \(error)")
      }
      #expect(trace.events.isEmpty)
    }
  }

  @Test func exactTTYCodeRunsOnceAndEmitsOnlySortedProductJSON() async throws {
    let trace = M2CommandTrace()
    let result = try await runM2ConnectOnceCommand(
      validArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: {
        trace.record("code")
        return "A1B2C3D4"
      },
      approval: approval(trace: trace, response: .line("A1B2C3D4")),
      signalMonitorFactory: {
        trace.record("monitor")
        return M2ManualSignalMonitor()
      },
      budgetFactory: {
        trace.record("budget")
        return ProductM2AbsoluteBudget.start()
      },
      runtime: { request, _ in
        trace.record("runtime:\(request.resourceDisplayName):\(request.sshTarget.rawValue)")
        return successReport(resource: request.resourceDisplayName)
      }
    )

    #expect(result.exitCode == 0)
    #expect(trace.count("code") == 1)
    #expect(trace.count("approval") == 1)
    #expect(trace.count("budget") == 1)
    #expect(trace.count("monitor") == 1)
    #expect(trace.count("runtime: Campus NC :thu21") == 1)
    #expect(
      trace.events == [
        "code", "approval", "budget", "monitor", "runtime: Campus NC :thu21",
      ])
    let prompt = try #require(trace.prompt)
    for marker in [
      " Campus NC ", "thu21", "A1B2C3D4", "authorized resource", "start_connection",
      "fresh SSH proof", "stop", "cleanup",
    ] {
      #expect(prompt.contains(marker))
    }
    #expect(!result.standardOutput.contains("A1B2C3D4"))
    assertSortedJSON(result.standardOutput)
  }

  @Test func deniedUnavailableAndInvalidCodesNeverConstructRuntimeOrMonitor() async throws {
    let cases: [(String, M2TTYLineRead)] = [
      ("A1B2C3D4", .line("A1B2C3D5")),
      ("A1B2C3D4", .unavailable),
      ("invalid", .line("invalid")),
    ]
    for (code, response) in cases {
      let trace = M2CommandTrace()
      let result = try await runM2ConnectOnceCommand(
        validArguments,
        authorizationAvailabilityFailure: { nil },
        generateApprovalCode: { code },
        approval: approval(trace: trace, response: response),
        signalMonitorFactory: {
          trace.record("monitor")
          return M2ManualSignalMonitor()
        },
        budgetFactory: {
          trace.record("budget")
          return ProductM2AbsoluteBudget.start()
        },
        runtime: { _, _ in
          trace.record("runtime")
          return successReport()
        }
      )

      #expect(result.exitCode == 77)
      #expect(trace.count("runtime") == 0)
      #expect(trace.count("budget") == 0)
      #expect(trace.count("monitor") == 0)
      #expect(trace.count("approval") == (code == "invalid" ? 0 : 1))
      assertSortedJSON(result.standardOutput)
    }
  }

  @Test func unavailableProviderStopsBeforeApprovalSignalAndRuntime() async throws {
    let trace = M2CommandTrace()
    let result = try await runM2ConnectOnceCommand(
      validArguments,
      authorizationAvailabilityFailure: { .providerUnavailable },
      generateApprovalCode: {
        trace.record("code")
        return "A1B2C3D4"
      },
      approval: approval(trace: trace, response: .line("A1B2C3D4")),
      signalMonitorFactory: {
        trace.record("monitor")
        return M2ManualSignalMonitor()
      },
      budgetFactory: {
        trace.record("budget")
        return ProductM2AbsoluteBudget.start()
      },
      runtime: { _, _ in
        trace.record("runtime")
        return successReport()
      }
    )

    #expect(result.exitCode == 69)
    #expect(trace.events.isEmpty)
    #expect(trace.prompt == nil)
    #expect(result.standardOutput.contains("\"containsSecrets\" : false"))
    #expect(result.standardOutput.contains("\"outcome\" : \"provider_unavailable\""))
    #expect(result.standardOutput.contains("\"runtimeInvoked\" : false"))
    #expect(!result.standardOutput.contains("Campus NC"))
    assertSortedJSON(result.standardOutput)
  }

  @Test func invocationParsesBothFormsAndRejectsMisplacedNonInteractiveFlag() throws {
    let tty = try parseM2ConnectOnceInvocation(m2ValidArguments)
    #expect(!tty.nonInteractive)
    #expect(
      tty.request
        == ProductM2ConnectRequest(resourceDisplayName: " Campus NC ", sshTarget: .thu21))

    let flagged = try parseM2ConnectOnceInvocation(
      arguments(name: "Campus").dropLast() + ["--non-interactive", "--json"])
    #expect(flagged.nonInteractive)
    #expect(
      flagged.request
        == ProductM2ConnectRequest(resourceDisplayName: "Campus", sshTarget: .thu21))

    let invalid = [
      [
        "m2", "connect-once", "--non-interactive", "--resource-display-name", "Campus",
        "--ssh-target", "thu21", "--json",
      ],
      // Flag between the name and --ssh-target.
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--non-interactive",
        "--ssh-target", "thu21", "--json",
      ],
      // Flag after --json.
      arguments(name: "Campus") + ["--non-interactive", "--json"].dropFirst(),
      // Duplicated flag.
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21",
        "--non-interactive", "--non-interactive", "--json",
      ],
      // Flag without the trailing --json.
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21",
        "--non-interactive",
      ],
      // Unknown flag in the optional slot.
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21",
        "--batch", "--json",
      ],
      // Flag with a value.
      [
        "m2", "connect-once", "--resource-display-name", "Campus", "--ssh-target", "thu21",
        "--non-interactive", "true", "--json",
      ],
    ]
    for candidate in invalid {
      #expect(throws: M2ConnectOnceCommandError.invalidArguments) {
        _ = try parseM2ConnectOnceInvocation(candidate)
      }
    }
  }

  @Test func nonInteractiveSkipsCodeAndApprovalAndAnnotatesReport() async throws {
    let trace = M2CommandTrace()
    let result = try await runM2ConnectOnceCommand(
      arguments(name: "Campus").dropLast() + ["--non-interactive", "--json"],
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: {
        trace.record("code")
        return "A1B2C3D4"
      },
      approval: approval(trace: trace, response: .line("WRONG1")),
      signalMonitorFactory: {
        trace.record("monitor")
        return M2ManualSignalMonitor()
      },
      budgetFactory: {
        trace.record("budget")
        return ProductM2AbsoluteBudget.start()
      },
      runtime: { request, _ in
        trace.record("runtime:\(request.resourceDisplayName)")
        return successReport(resource: request.resourceDisplayName)
      }
    )

    #expect(result.exitCode == 0)
    #expect(trace.count("code") == 0)
    #expect(trace.count("approval") == 0)
    #expect(trace.count("budget") == 1)
    #expect(trace.count("monitor") == 1)
    #expect(trace.count("runtime:Campus") == 1)
    #expect(result.standardOutput.contains("\"approvalMode\" : \"non_interactive\""))
    #expect(result.standardOutput.contains("\"schemaVersion\" : 14"))
    #expect(result.standardOutput.contains("\"containsSecrets\" : false"))
    #expect(!result.standardOutput.contains("A1B2C3D4"))
    assertSortedJSON(result.standardOutput)
  }

  @Test func ttyModeReportsApprovalModeAndStillRequiresExactCode() async throws {
    let trace = M2CommandTrace()
    let accepted = try await runM2ConnectOnceCommand(
      m2ValidArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: { "A1B2C3D4" },
      approval: approval(trace: trace, response: .line("A1B2C3D4")),
      runtime: { _, _ in successReport(resource: " Campus NC ") }
    )
    #expect(accepted.exitCode == 0)
    #expect(accepted.standardOutput.contains("\"approvalMode\" : \"tty_code\""))
    assertSortedJSON(accepted.standardOutput)

    // A mistyped code still denies before any runtime work, and the denial
    // lifecycle report carries no approvalMode.
    let denied = try await runM2ConnectOnceCommand(
      m2ValidArguments,
      authorizationAvailabilityFailure: { nil },
      generateApprovalCode: { "A1B2C3D4" },
      approval: approval(trace: trace, response: .line("A1B2C3D5")),
      runtime: { _, _ in
        Issue.record("runtime must not run after denial")
        return successReport()
      }
    )
    #expect(denied.exitCode == 77)
    #expect(!denied.standardOutput.contains("approvalMode"))
  }

  @Test func nonInteractiveStillHonorsAvailabilityGate() async throws {
    let trace = M2CommandTrace()
    let result = try await runM2ConnectOnceCommand(
      arguments(name: "Campus").dropLast() + ["--non-interactive", "--json"],
      authorizationAvailabilityFailure: { .providerUnavailable },
      generateApprovalCode: {
        trace.record("code")
        return "A1B2C3D4"
      },
      approval: approval(trace: trace, response: .line("A1B2C3D4")),
      runtime: { _, _ in
        trace.record("runtime")
        return successReport()
      }
    )

    #expect(result.exitCode == 69)
    #expect(trace.events.isEmpty)
    #expect(result.standardOutput.contains("\"outcome\" : \"provider_unavailable\""))
  }

  private func arguments(name: String, target: String = "thu21") -> [String] {
    [
      "m2", "connect-once", "--resource-display-name", name,
      "--ssh-target", target, "--json",
    ]
  }
}
