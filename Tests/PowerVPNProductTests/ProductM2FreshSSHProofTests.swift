import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2FreshSSHProofTests {
  private let target = ProductM2SSHTarget.thu21
  private let expected = Data("POWERVPN_M2:0123456789abcdef0123456789abcdef\n".utf8)

  @Test func exactChallengeAndZeroExitAreProven() {
    let evidence = assess(
      .init(
        processStarted: true, exitStatus: 0, standardOutput: expected))
    #expect(evidence.outcome == .proven)
    #expect(evidence.challengeMatched)
    #expect(evidence.exitStatusZero)
    #expect(evidence.automaticRetryCount == 0)
  }

  @Test func staleOrNonExactOutputIsRejected() {
    let rejected = [
      Data("POWERVPN_M2:ffffffffffffffffffffffffffffffff\n".utf8),
      Data("SSH-2.0-OpenSSH_9.9\r\n".utf8),
      Data("POWERVPN_M2:0123456789abcdef0123456789abcdef".utf8),
      expected + Data("extra\n".utf8),
      expected + expected,
    ]
    for output in rejected {
      #expect(
        assess(
          .init(
            processStarted: true, exitStatus: 0, standardOutput: output
          )
        ).outcome == .rejected)
    }
  }

  @Test func processAndOutputFailuresAreRejected() {
    let cases = [
      ProductM2FreshSSHProcessResult(processStarted: false, exitStatus: nil),
      ProductM2FreshSSHProcessResult(
        processStarted: true, exitStatus: 255, standardOutput: expected),
      ProductM2FreshSSHProcessResult(
        processStarted: true, exitStatus: 0, standardOutput: expected,
        standardOutputWithinLimit: false),
      ProductM2FreshSSHProcessResult(
        processStarted: true, exitStatus: 0, standardOutput: expected,
        standardErrorWithinLimit: false),
    ]
    for result in cases {
      let evidence = assess(result)
      #expect(evidence.outcome == .rejected)
      if !result.processStarted { #expect(!evidence.challengeMatched) }
    }
  }

  @Test func emptyExpectedOutputCanNeverProveAChallenge() {
    let evidence = ProductM2FreshSSHProofAssessment.assess(
      target: target,
      expectedStandardOutput: Data(),
      result: ProductM2FreshSSHProcessResult(
        processStarted: false, processReaped: false, exitStatus: nil)
    )
    #expect(evidence.outcome == .rejected)
    #expect(!evidence.challengeMatched)
  }

  @Test func boundedRunnerTerminalOutcomesMapWithoutRetry() {
    let cases:
      [(
        BoundedCommandOutcome, ProductM2SSHProofOutcome, Bool, Bool
      )] = [
        (.stdoutLimitExceeded, .rejected, false, true),
        (.stderrLimitExceeded, .rejected, true, false),
        (.timedOut, .timedOut, true, true),
        (.cancelled, .cancelled, true, true),
        (.launchFailed, .rejected, true, true),
        (.ioFailed, .rejected, true, true),
        (.invalidRequest, .rejected, true, true),
      ]
    for (bounded, expectedOutcome, stdoutWithinLimit, stderrWithinLimit) in cases {
      let process = ProductM2FreshSSHProcessResult(
        boundedOutcome: bounded,
        processStarted: bounded != .launchFailed && bounded != .invalidRequest,
        processReaped: bounded != .launchFailed && bounded != .invalidRequest,
        exitStatus: nil
      )
      let evidence = assess(process)
      #expect(evidence.outcome == expectedOutcome)
      #expect(evidence.standardOutputWithinLimit == stdoutWithinLimit)
      #expect(evidence.standardErrorWithinLimit == stderrWithinLimit)
      #expect(evidence.automaticRetryCount == 0)
    }
  }

  @Test func cancellationPrecedesTimeoutAndTimeoutPrecedesOtherFailures() {
    let cancelled = assess(
      .init(
        processStarted: true, exitStatus: 0, standardOutput: expected,
        timedOut: true, cancelled: true))
    #expect(cancelled.outcome == .cancelled)
    let timedOut = assess(
      .init(
        processStarted: true, exitStatus: 0, standardOutput: expected,
        timedOut: true))
    #expect(timedOut.outcome == .timedOut)
  }

  @Test func encodedEvidenceContainsNoChallengeOrRawProcessOutput() throws {
    let evidence = assess(
      .init(
        processStarted: true, exitStatus: 0, standardOutput: expected,
        standardError: Data("sensitive-canary".utf8)))
    let encoded = String(decoding: try JSONEncoder().encode(evidence), as: UTF8.self)
    #expect(!encoded.contains("0123456789abcdef"))
    #expect(!encoded.contains("sensitive-canary"))
    #expect(encoded.contains("\"containsChallenge\":false"))
    #expect(encoded.contains("\"containsRawOutput\":false"))
    #expect(encoded.contains("\"containsSecrets\":false"))
  }

  private func assess(
    _ result: ProductM2FreshSSHProcessResult
  ) -> ProductM2FreshSSHProofEvidence {
    ProductM2FreshSSHProofAssessment.assess(
      target: target, expectedStandardOutput: expected, result: result)
  }
}
