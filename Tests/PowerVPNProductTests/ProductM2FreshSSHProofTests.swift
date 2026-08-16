import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2FreshSSHProofTests {
  private let target = ProductM2SSHTarget.thu21
  private let expected = Data("POWERVPN_M2:0123456789abcdef0123456789abcdef\n".utf8)

  @Test func exactChallengeAndZeroExitAreProven() throws {
    let evidence = assess(
      .init(
        processStarted: true, exitStatus: 0, standardOutput: expected))
    #expect(evidence.outcome == .proven)
    #expect(evidence.challengeMatched)
    #expect(evidence.exitStatusZero)
    #expect(evidence.automaticRetryCount == 0)
    #expect(evidence.failureClass == nil)
    let encoded = String(decoding: try JSONEncoder().encode(evidence), as: UTF8.self)
    #expect(!encoded.contains("\"failureClass\""))
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
      let evidence = assess(
        .init(
          processStarted: true, exitStatus: 0, standardOutput: output
        ))
      #expect(evidence.outcome == .rejected)
      #expect(evidence.failureClass == .outputInvalid)
    }
  }

  @Test func processAndOutputFailuresAreRejectedWithClosedClasses() {
    let cases: [(ProductM2FreshSSHProcessResult, ProductM2SSHFailureClass)] = [
      (.init(processStarted: false, exitStatus: nil), .unclassified),
      (.init(processStarted: true, exitStatus: 255), .unclassified),
      (
        .init(
          processStarted: true, exitStatus: 0, standardOutput: expected,
          standardOutputWithinLimit: false),
        .outputInvalid
      ),
      (
        .init(
          processStarted: true, exitStatus: 0, standardOutput: expected,
          standardErrorWithinLimit: false),
        .outputInvalid
      ),
    ]
    for (result, failureClass) in cases {
      let evidence = assess(result)
      #expect(evidence.outcome == .rejected)
      #expect(evidence.failureClass == failureClass)
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
    #expect(evidence.failureClass == .unclassified)
  }

  @Test func boundedRunnerTerminalOutcomesMapWithoutRetry() {
    let cases:
      [(
        BoundedCommandOutcome, ProductM2SSHProofOutcome,
        ProductM2SSHFailureClass?, Bool, Bool
      )] = [
        (.stdoutLimitExceeded, .rejected, .outputInvalid, false, true),
        (.stderrLimitExceeded, .rejected, .outputInvalid, true, false),
        (.timedOut, .timedOut, nil, true, true),
        (.cancelled, .cancelled, nil, true, true),
        (.launchFailed, .rejected, .unclassified, true, true),
        (.ioFailed, .rejected, .unclassified, true, true),
        (.invalidRequest, .rejected, .configError, true, true),
      ]
    for (bounded, expectedOutcome, failureClass, stdoutWithinLimit, stderrWithinLimit)
      in cases
    {
      let process = ProductM2FreshSSHProcessResult(
        boundedOutcome: bounded,
        processStarted: bounded != .launchFailed && bounded != .invalidRequest,
        processReaped: bounded != .launchFailed && bounded != .invalidRequest,
        exitStatus: nil
      )
      let evidence = assess(process)
      #expect(evidence.outcome == expectedOutcome)
      #expect(evidence.failureClass == failureClass)
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
    #expect(cancelled.failureClass == nil)
    let timedOut = assess(
      .init(
        processStarted: true, exitStatus: 0, standardOutput: expected,
        timedOut: true))
    #expect(timedOut.outcome == .timedOut)
    #expect(timedOut.failureClass == nil)
  }

  @Test func deterministicCLocaleFailuresMapWithoutRetainingRawText() throws {
    let fixtures: [(String, ProductM2SSHFailureClass)] = [
      (
        "ssh: connect to host secret-host port 22: Operation timed out\r\n",
        .targetUnreachable
      ),
      (
        "ssh: connect to host secret-host port 22: Connection refused\r\n",
        .transportRefused
      ),
      ("Host key verification failed.\r\nkey-canary", .hostKeyRejected),
      ("user-canary: Permission denied (publickey).\r\n", .authRejected),
      ("command-line line 0: Bad configuration option: path-canary\r\n", .configError),
    ]
    for (text, expectedClass) in fixtures {
      let failureClass = classify(text)
      #expect(failureClass == expectedClass)
      let evidence = assess(
        .init(
          processStarted: true,
          exitStatus: 255,
          failureClass: failureClass
        ))
      let data = try JSONEncoder().encode(evidence)
      let encoded = String(decoding: data, as: UTF8.self)
      let object = try #require(
        JSONSerialization.jsonObject(with: data) as? [String: Any])
      #expect(object["failureClass"] as? String == expectedClass.rawValue)
      #expect(object["exitStatus"] == nil)
      #expect(object["standardError"] == nil)
      #expect(!encoded.contains("secret-host"))
      #expect(!encoded.contains("user-canary"))
      #expect(!encoded.contains("path-canary"))
      #expect(!encoded.contains("key-canary"))
      #expect(!encoded.contains("0123456789abcdef"))
      #expect(encoded.contains("\"containsChallenge\":false"))
      #expect(encoded.contains("\"containsRawOutput\":false"))
      #expect(encoded.contains("\"containsSecrets\":false"))
    }
  }

  @Test func unmatchedExitAndSignalClassificationStayConservative() {
    #expect(classify("unmatched-client-canary") == nil)
    #expect(classify("") == nil)

    let clientFailure = assess(
      ProductM2FreshSSHProcessResult(
        boundedOutcome: .exited,
        processStarted: true,
        processReaped: true,
        exitStatus: 255
      ))
    #expect(clientFailure.failureClass == .unclassified)

    let remoteFailure = assess(
      ProductM2FreshSSHProcessResult(
        boundedOutcome: .exited,
        processStarted: true,
        processReaped: true,
        exitStatus: 23
      ))
    #expect(remoteFailure.failureClass == .remoteCommandRejected)

    let signalFailure = assess(
      ProductM2FreshSSHProcessResult(
        boundedOutcome: .exited,
        processStarted: true,
        processReaped: true,
        exitStatus: 15,
        exitedNormally: false,
        detectedFailureClass: .authRejected
      ))
    #expect(signalFailure.failureClass == .unclassified)
  }

  @Test func remoteExitStatusPrecedesSpoofableStandardError() {
    let detected: [ProductM2SSHFailureClass] = [
      .authRejected, .configError, .targetUnreachable,
    ]
    for detectedFailureClass in detected {
      let remote = assess(
        ProductM2FreshSSHProcessResult(
          boundedOutcome: .exited,
          processStarted: true,
          processReaped: true,
          exitStatus: 23,
          detectedFailureClass: detectedFailureClass
        ))
      #expect(remote.failureClass == .remoteCommandRejected)

      let sshClient = assess(
        ProductM2FreshSSHProcessResult(
          boundedOutcome: .exited,
          processStarted: true,
          processReaped: true,
          exitStatus: 255,
          detectedFailureClass: detectedFailureClass
        ))
      #expect(sshClient.failureClass == detectedFailureClass)
    }
  }

  private func classify(_ text: String) -> ProductM2SSHFailureClass? {
    Data(text.utf8).withUnsafeBytes {
      ProductM2SSHFailureClassifier.classify($0)
    }
  }

  private func assess(
    _ result: ProductM2FreshSSHProcessResult
  ) -> ProductM2FreshSSHProofEvidence {
    ProductM2FreshSSHProofAssessment.assess(
      target: target, expectedStandardOutput: expected, result: result)
  }
}
