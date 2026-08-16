import Foundation
import PowerVPNCore
import Security

package struct ProductM2FreshSSHProver: Sendable {
  package typealias Execute =
    @Sendable (ProductM2FreshSSHCommand, Int) async -> ProductM2FreshSSHProcessResult

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
    sshAuthSocket: String? = ProcessInfo.processInfo.environment[
      BoundedCommandRequest.sshAuthSocketEnvironmentKey
    ],
    runner: BoundedCommandRunner = BoundedCommandRunner()
  ) {
    self.init(
      homeDirectory: homeDirectory,
      generateChallenge: secureChallenge,
      execute: { command, timeoutMilliseconds in
        let result = await runner.run(
          BoundedCommandRequest(
            executable: ProductM2FreshSSHCommand.executable,
            arguments: command.arguments,
            timeoutMilliseconds: timeoutMilliseconds,
            stdoutLimitBytes: ProductM2FreshSSHCommand.outputLimitBytes,
            stderrLimitBytes: ProductM2FreshSSHCommand.outputLimitBytes,
            environment: sshAuthSocket.map {
              [BoundedCommandRequest.sshAuthSocketEnvironmentKey: $0]
            } ?? [:],
            failureOutputPolicy: .retainStandardErrorOnNonzeroExit
          ))
        return ProductM2FreshSSHProcessResult(result)
      }
    )
  }

  package func prove(
    _ target: ProductM2SSHTarget,
    timeoutMilliseconds: Int
  ) async -> ProductM2FreshSSHProofEvidence {
    guard (1...ProductM2FreshSSHCommand.timeoutMilliseconds).contains(timeoutMilliseconds)
    else { return .timedOut(target: target) }
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
    var result = await execute(command, timeoutMilliseconds)
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
    var detectedFailureClass: ProductM2SSHFailureClass?
    if result.outcome == .exited,
      result.exitedNormally,
      result.exitStatus == 255
    {
      result.consumeRetainedFailureStandardError { bytes in
        detectedFailureClass = ProductM2SSHFailureClassifier.classify(bytes)
      }
    }
    self.init(
      boundedOutcome: result.outcome,
      processStarted: result.started,
      processReaped: result.reaped,
      exitStatus: result.exitStatus,
      exitedNormally: result.exitedNormally,
      standardOutput: result.stdout,
      detectedFailureClass: detectedFailureClass
    )
  }

  package init(
    boundedOutcome: BoundedCommandOutcome,
    processStarted: Bool,
    processReaped: Bool,
    exitStatus: Int32?,
    exitedNormally: Bool = true,
    standardOutput: Data = Data(),
    detectedFailureClass: ProductM2SSHFailureClass? = nil
  ) {
    let failureClass: ProductM2SSHFailureClass?
    switch boundedOutcome {
    case .timedOut, .cancelled:
      failureClass = nil
    case .stdoutLimitExceeded, .stderrLimitExceeded:
      failureClass = .outputInvalid
    case .invalidRequest:
      failureClass = .configError
    case .exited where exitStatus == 0:
      failureClass = nil
    case .exited:
      if !exitedNormally {
        failureClass = .unclassified
      } else if let exitStatus, (1...254).contains(Int(exitStatus)) {
        failureClass = .remoteCommandRejected
      } else if exitStatus == 255, let detectedFailureClass {
        failureClass = detectedFailureClass
      } else {
        failureClass = .unclassified
      }
    case .launchFailed, .ioFailed:
      failureClass = .unclassified
    }
    self.init(
      processStarted: processStarted,
      processReaped: processReaped,
      exitStatus: exitStatus,
      standardOutput: standardOutput,
      standardOutputWithinLimit: boundedOutcome != .stdoutLimitExceeded,
      standardErrorWithinLimit: boundedOutcome != .stderrLimitExceeded,
      timedOut: boundedOutcome == .timedOut,
      cancelled: boundedOutcome == .cancelled,
      failureClass: failureClass
    )
  }
}

package enum ProductM2SSHFailureClassifier {
  private static let directConnect = Array("ssh: connect to host ".utf8)
  private static let operationTimedOut = Array(": Operation timed out".utf8)
  private static let connectionTimedOut = Array(": Connection timed out".utf8)
  private static let noRoute = Array(": No route to host".utf8)
  private static let networkUnreachable = Array(": Network is unreachable".utf8)
  private static let connectionRefused = Array(": Connection refused".utf8)
  private static let hostKeyFailed = Array("Host key verification failed.".utf8)
  private static let hostKeyChanged =
    Array("REMOTE HOST IDENTIFICATION HAS CHANGED!".utf8)
  private static let noKnownHostKey = Array("host key is known for".utf8)
  private static let strictChecking = Array("strict checking.".utf8)
  private static let permissionDenied = Array("Permission denied (".utf8)
  private static let authExhausted =
    Array("No more authentication methods to try.".utf8)
  private static let commandLineError = Array("command-line line 0:".utf8)
  private static let hostnameResolutionFailed =
    Array("Could not resolve hostname ".utf8)

  package static func classify(
    _ standardError: UnsafeRawBufferPointer
  ) -> ProductM2SSHFailureClass? {
    if contains(standardError, directConnect),
      containsAny(
        standardError,
        [operationTimedOut, connectionTimedOut, noRoute, networkUnreachable]
      )
    {
      return .targetUnreachable
    }
    if contains(standardError, directConnect),
      contains(standardError, connectionRefused)
    {
      return .transportRefused
    }
    if containsAny(standardError, [hostKeyFailed, hostKeyChanged])
      || (contains(standardError, noKnownHostKey)
        && contains(standardError, strictChecking))
    {
      return .hostKeyRejected
    }
    if containsAny(standardError, [permissionDenied, authExhausted]) {
      return .authRejected
    }
    if containsAny(standardError, [commandLineError, hostnameResolutionFailed]) {
      return .configError
    }
    return nil
  }

  private static func containsAny(
    _ bytes: UnsafeRawBufferPointer,
    _ needles: [[UInt8]]
  ) -> Bool {
    needles.contains { contains(bytes, $0) }
  }

  private static func contains(
    _ bytes: UnsafeRawBufferPointer,
    _ needle: [UInt8]
  ) -> Bool {
    guard !needle.isEmpty, needle.count <= bytes.count else { return false }
    let haystack = bytes.bindMemory(to: UInt8.self)
    for start in 0...(haystack.count - needle.count) {
      var matched = true
      for offset in needle.indices where haystack[start + offset] != needle[offset] {
        matched = false
        break
      }
      if matched { return true }
    }
    return false
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
