import Foundation
import PowerVPNCore
import Security

package struct ProductM2FreshSSHProver: Sendable {
  package typealias Execute =
    @Sendable (ProductM2FreshSSHCommand) async -> ProductM2FreshSSHProcessResult

  private let homeDirectory: String
  private let generateChallenge: @Sendable () throws -> String
  private let execute: Execute

  package init(
    homeDirectory: String,
    generateChallenge: @escaping @Sendable () throws -> String = secureChallenge,
    execute: @escaping Execute
  ) {
    self.homeDirectory = homeDirectory
    self.generateChallenge = generateChallenge
    self.execute = execute
  }

  package init(
    homeDirectory: String = FileManager.default.homeDirectoryForCurrentUser.path,
    runner: BoundedCommandRunner = BoundedCommandRunner()
  ) {
    self.init(
      homeDirectory: homeDirectory,
      generateChallenge: secureChallenge,
      execute: { command in
        let result = await runner.run(
          BoundedCommandRequest(
            executable: ProductM2FreshSSHCommand.executable,
            arguments: command.arguments,
            timeoutMilliseconds: ProductM2FreshSSHCommand.timeoutMilliseconds,
            stdoutLimitBytes: ProductM2FreshSSHCommand.outputLimitBytes,
            stderrLimitBytes: ProductM2FreshSSHCommand.outputLimitBytes
          ))
        return ProductM2FreshSSHProcessResult(result)
      }
    )
  }

  package func prove(
    _ target: ProductM2SSHTarget
  ) async -> ProductM2FreshSSHProofEvidence {
    if Task.isCancelled { return unstarted(target: target, cancelled: true) }
    let command: ProductM2FreshSSHCommand
    do {
      command = try ProductM2FreshSSHCommand.make(
        target: target,
        challenge: generateChallenge(),
        homeDirectory: homeDirectory
      )
    } catch {
      return unstarted(target: target, cancelled: false)
    }
    if Task.isCancelled { return unstarted(target: target, cancelled: true) }
    var result = await execute(command)
    if Task.isCancelled, !result.cancelled {
      result = ProductM2FreshSSHProcessResult(
        processStarted: result.processStarted,
        processReaped: result.processReaped,
        exitStatus: result.exitStatus,
        standardOutputWithinLimit: result.standardOutputWithinLimit,
        standardErrorWithinLimit: result.standardErrorWithinLimit,
        timedOut: result.timedOut,
        cancelled: true
      )
    }
    return ProductM2FreshSSHProofAssessment.assess(
      target: target,
      expectedStandardOutput: command.expectedStandardOutput,
      result: result
    )
  }

  private func unstarted(
    target: ProductM2SSHTarget,
    cancelled: Bool
  ) -> ProductM2FreshSSHProofEvidence {
    ProductM2FreshSSHProofAssessment.assess(
      target: target,
      expectedStandardOutput: Data(),
      result: ProductM2FreshSSHProcessResult(
        processStarted: false,
        processReaped: false,
        exitStatus: nil,
        cancelled: cancelled
      )
    )
  }
}

extension ProductM2FreshSSHProcessResult {
  fileprivate init(_ result: BoundedCommandResult) {
    self.init(
      boundedOutcome: result.outcome,
      processStarted: result.started,
      processReaped: result.reaped,
      exitStatus: result.exitStatus,
      standardOutput: result.stdout,
      standardError: result.stderr
    )
  }

  package init(
    boundedOutcome: BoundedCommandOutcome,
    processStarted: Bool,
    processReaped: Bool,
    exitStatus: Int32?,
    standardOutput: Data = Data(),
    standardError: Data = Data()
  ) {
    self.init(
      processStarted: processStarted,
      processReaped: processReaped,
      exitStatus: exitStatus,
      standardOutput: standardOutput,
      standardError: standardError,
      standardOutputWithinLimit: boundedOutcome != .stdoutLimitExceeded,
      standardErrorWithinLimit: boundedOutcome != .stderrLimitExceeded,
      timedOut: boundedOutcome == .timedOut,
      cancelled: boundedOutcome == .cancelled
    )
  }
}

private func secureChallenge() throws -> String {
  var bytes = [UInt8](repeating: 0, count: 16)
  let status = bytes.withUnsafeMutableBytes { buffer in
    SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
  }
  guard status == errSecSuccess else { throw ProductM2SecureChallengeError.failed }
  let digits = Array("0123456789abcdef".utf8)
  var encoded = [UInt8]()
  encoded.reserveCapacity(32)
  for byte in bytes {
    encoded.append(digits[Int(byte >> 4)])
    encoded.append(digits[Int(byte & 0x0F)])
  }
  return String(decoding: encoded, as: UTF8.self)
}

private enum ProductM2SecureChallengeError: Error {
  case failed
}
