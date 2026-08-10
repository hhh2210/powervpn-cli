import Foundation

public struct ProductM2FreshSSHProofEvidence: Encodable, Equatable, Sendable {
  public let target: ProductM2SSHTarget
  public let outcome: ProductM2SSHProofOutcome
  public let processStarted: Bool
  public let processReaped: Bool
  public let freshTransportForced: Bool
  public let strictHostKeyPolicy: Bool
  public let exitStatusZero: Bool
  public let challengeMatched: Bool
  public let standardOutputWithinLimit: Bool
  public let standardErrorWithinLimit: Bool
  public let timedOut: Bool
  public let cancelled: Bool
  public let automaticRetryCount = 0
  public let containsChallenge = false
  public let containsRawOutput = false
  public let containsSecrets = false

  package init(
    target: ProductM2SSHTarget,
    outcome: ProductM2SSHProofOutcome,
    processStarted: Bool,
    processReaped: Bool,
    exitStatusZero: Bool,
    challengeMatched: Bool,
    standardOutputWithinLimit: Bool,
    standardErrorWithinLimit: Bool,
    timedOut: Bool,
    cancelled: Bool
  ) {
    self.target = target
    self.outcome = outcome
    self.processStarted = processStarted
    self.processReaped = processReaped
    freshTransportForced = processStarted
    strictHostKeyPolicy = processStarted
    self.exitStatusZero = exitStatusZero
    self.challengeMatched = challengeMatched
    self.standardOutputWithinLimit = standardOutputWithinLimit
    self.standardErrorWithinLimit = standardErrorWithinLimit
    self.timedOut = timedOut
    self.cancelled = cancelled
  }
}

package struct ProductM2FreshSSHProcessResult: Sendable {
  package let processStarted: Bool
  package let processReaped: Bool
  package let exitStatus: Int32?
  package let standardOutput: Data
  package let standardError: Data
  package let standardOutputWithinLimit: Bool
  package let standardErrorWithinLimit: Bool
  package let timedOut: Bool
  package let cancelled: Bool

  package init(
    processStarted: Bool,
    processReaped: Bool = true,
    exitStatus: Int32?,
    standardOutput: Data = Data(),
    standardError: Data = Data(),
    standardOutputWithinLimit: Bool = true,
    standardErrorWithinLimit: Bool = true,
    timedOut: Bool = false,
    cancelled: Bool = false
  ) {
    self.processStarted = processStarted
    self.processReaped = processReaped
    self.exitStatus = exitStatus
    self.standardOutput = standardOutput
    self.standardError = standardError
    self.standardOutputWithinLimit = standardOutputWithinLimit
    self.standardErrorWithinLimit = standardErrorWithinLimit
    self.timedOut = timedOut
    self.cancelled = cancelled
  }
}

package enum ProductM2FreshSSHProofAssessment {
  package static func assess(
    target: ProductM2SSHTarget,
    expectedStandardOutput: Data,
    result: ProductM2FreshSSHProcessResult
  ) -> ProductM2FreshSSHProofEvidence {
    let challengeMatched =
      result.processStarted && !expectedStandardOutput.isEmpty
      && result.standardOutput == expectedStandardOutput
    let outcome: ProductM2SSHProofOutcome
    if result.cancelled {
      outcome = .cancelled
    } else if result.timedOut {
      outcome = .timedOut
    } else if result.processStarted, result.processReaped, result.exitStatus == 0,
      challengeMatched, result.standardOutputWithinLimit,
      result.standardErrorWithinLimit
    {
      outcome = .proven
    } else {
      outcome = .rejected
    }
    return ProductM2FreshSSHProofEvidence(
      target: target,
      outcome: outcome,
      processStarted: result.processStarted,
      processReaped: result.processReaped,
      exitStatusZero: result.exitStatus == 0,
      challengeMatched: challengeMatched,
      standardOutputWithinLimit: result.standardOutputWithinLimit,
      standardErrorWithinLimit: result.standardErrorWithinLimit,
      timedOut: result.timedOut,
      cancelled: result.cancelled
    )
  }
}
