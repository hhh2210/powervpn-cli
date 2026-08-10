import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2FreshSSHProverTests {
  private let challenge = "0123456789abcdef0123456789abcdef"

  @Test func successfulProofExecutesExactlyOnce() async {
    let trace = FreshSSHExecutionTrace()
    let prover = ProductM2FreshSSHProver(
      homeDirectory: "/Users/tester",
      generateChallenge: { challenge },
      execute: { command, _ in
        await trace.record(command)
        return ProductM2FreshSSHProcessResult(
          processStarted: true,
          exitStatus: 0,
          standardOutput: command.expectedStandardOutput
        )
      }
    )
    let evidence = await prover.prove(.thu52, timeoutMilliseconds: 15_000)
    #expect(evidence.outcome == .proven)
    #expect(await trace.count == 1)
    #expect(await trace.targets == [.thu52])
  }

  @Test func executionFailureHasNoAutomaticRetry() async {
    let trace = FreshSSHExecutionTrace()
    let prover = ProductM2FreshSSHProver(
      homeDirectory: "/Users/tester",
      generateChallenge: { challenge },
      execute: { command, _ in
        await trace.record(command)
        return ProductM2FreshSSHProcessResult(
          processStarted: true, exitStatus: 255)
      }
    )
    let evidence = await prover.prove(.thu21, timeoutMilliseconds: 15_000)
    #expect(evidence.outcome == .rejected)
    #expect(evidence.automaticRetryCount == 0)
    #expect(await trace.count == 1)
  }

  @Test func preCancelledTaskNeverGeneratesOrExecutes() async {
    let trace = FreshSSHExecutionTrace()
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return await ProductM2FreshSSHProver(
        homeDirectory: "/Users/tester",
        generateChallenge: {
          Issue.record("challenge generation must not run")
          return self.challenge
        },
        execute: { command, _ in
          await trace.record(command)
          return ProductM2FreshSSHProcessResult(processStarted: true, exitStatus: 0)
        }
      ).prove(.thu21, timeoutMilliseconds: 15_000)
    }
    let evidence = await task.value
    #expect(evidence.outcome == .cancelled)
    #expect(await trace.count == 0)
  }

  @Test func challengeGenerationFailureRejectsWithoutExecution() async {
    let trace = FreshSSHExecutionTrace()
    let prover = ProductM2FreshSSHProver(
      homeDirectory: "/Users/tester",
      generateChallenge: { throw FreshSSHTestError.failed },
      execute: { command, _ in
        await trace.record(command)
        return ProductM2FreshSSHProcessResult(processStarted: true, exitStatus: 0)
      }
    )
    let evidence = await prover.prove(.thu21, timeoutMilliseconds: 15_000)
    #expect(evidence.outcome == .rejected)
    #expect(!evidence.processStarted)
    #expect(!evidence.challengeMatched)
    #expect(!evidence.freshTransportForced)
    #expect(!evidence.strictHostKeyPolicy)
    #expect(await trace.count == 0)
  }

  @Test func invalidSSHAuthSocketRejectsBeforeProcessLaunch() async {
    let evidence = await ProductM2FreshSSHProver(
      homeDirectory: "/Users/tester",
      sshAuthSocket: "relative-agent-socket"
    ).prove(.thu21, timeoutMilliseconds: 15_000)
    #expect(evidence.outcome == .rejected)
    #expect(!evidence.processStarted)
    #expect(!evidence.processReaped)
  }
}

private actor FreshSSHExecutionTrace {
  private var commands: [ProductM2FreshSSHCommand] = []

  func record(_ command: ProductM2FreshSSHCommand) { commands.append(command) }
  var count: Int { commands.count }
  var targets: [ProductM2SSHTarget] { commands.map(\.target) }
}

private enum FreshSSHTestError: Error {
  case failed
}
