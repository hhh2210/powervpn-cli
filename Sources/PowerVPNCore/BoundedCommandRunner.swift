import Foundation

package enum BoundedCommandOutcome: String, Equatable, Sendable {
  case exited
  case launchFailed = "launch_failed"
  case timedOut = "timed_out"
  case cancelled
  case stdoutLimitExceeded = "stdout_limit_exceeded"
  case stderrLimitExceeded = "stderr_limit_exceeded"
  case ioFailed = "io_failed"
  case invalidRequest = "invalid_request"
}
package enum BoundedCommandFailureOutputPolicy: Equatable, Sendable {
  case discard
  case retainStandardErrorOnNonzeroExit
}

package struct BoundedCommandRequest: Equatable, Sendable {
  package static let sshAuthSocketEnvironmentKey = "SSH_AUTH_SOCK"

  package let executable: String
  package let arguments: [String]
  package let timeoutMilliseconds: Int
  package let stdoutLimitBytes: Int
  package let stderrLimitBytes: Int
  package let environment: [String: String]
  package let failureOutputPolicy: BoundedCommandFailureOutputPolicy

  package init(
    executable: String,
    arguments: [String],
    timeoutMilliseconds: Int,
    stdoutLimitBytes: Int,
    stderrLimitBytes: Int,
    environment: [String: String] = [:],
    failureOutputPolicy: BoundedCommandFailureOutputPolicy = .discard
  ) {
    self.executable = executable
    self.arguments = arguments
    self.timeoutMilliseconds = timeoutMilliseconds
    self.stdoutLimitBytes = stdoutLimitBytes
    self.stderrLimitBytes = stderrLimitBytes
    self.environment = environment
    self.failureOutputPolicy = failureOutputPolicy
  }

  var isValid: Bool {
    executable.hasPrefix("/")
      && URL(fileURLWithPath: executable).standardizedFileURL.path == executable
      && !Self.forbiddenExecutableNames.contains(
        URL(fileURLWithPath: executable).lastPathComponent
      )
      && !executable.utf8.contains(0)
      && arguments.allSatisfy({ !$0.utf8.contains(0) })
      && arguments.count <= 4_096
      && arguments.allSatisfy({ $0.utf8.count <= 1_048_576 })
      && arguments.reduce(0, { $0 + $1.utf8.count }) <= 1_048_576
      && Self.isValidEnvironment(environment)
      && (1...60_000).contains(timeoutMilliseconds)
      && (1...16_777_216).contains(stdoutLimitBytes)
      && (1...16_777_216).contains(stderrLimitBytes)
  }

  private static let forbiddenExecutableNames: Set<String> = [
    "bash", "csh", "dash", "env", "fish", "ksh", "sh", "tcsh", "zsh",
  ]

  private static func isValidEnvironment(_ environment: [String: String]) -> Bool {
    guard environment.keys.allSatisfy({ $0 == sshAuthSocketEnvironmentKey }) else {
      return false
    }
    guard let socket = environment[sshAuthSocketEnvironmentKey] else { return true }
    return socket.hasPrefix("/")
      && (1...1_024).contains(socket.utf8.count)
      && !socket.utf8.contains(0)
      && socket.rangeOfCharacter(from: .newlines) == nil
  }
}

private final class BoundedCommandFailureOutputBuffer: @unchecked Sendable {
  private let lock = NSLock()
  private var bytes: Data

  init(_ bytes: Data) {
    self.bytes = bytes
  }

  func consume(_ body: (UnsafeRawBufferPointer) -> Void) {
    let consumed: Data? = lock.withLock {
      guard !bytes.isEmpty else { return nil }
      let value = bytes
      bytes = Data()
      return value
    }
    guard var consumed else { return }
    defer {
      consumed.resetBytes(in: consumed.indices)
      consumed.removeAll(keepingCapacity: false)
    }
    consumed.withUnsafeBytes(body)
  }
}

package struct BoundedCommandResult: Equatable, Sendable {
  package let outcome: BoundedCommandOutcome
  package let started: Bool
  package let exitStatus: Int32?
  package let exitedNormally: Bool
  package let stdout: Data
  package let stderr: Data
  package let terminationRequested: Bool
  package let killRequested: Bool
  package let reaped: Bool
  private let failureStandardError: BoundedCommandFailureOutputBuffer?

  package init(
    outcome: BoundedCommandOutcome,
    started: Bool,
    exitStatus: Int32?,
    exitedNormally: Bool = true,
    stdout: Data,
    stderr: Data,
    terminationRequested: Bool,
    killRequested: Bool,
    reaped: Bool,
    retainedFailureStandardError: Data = Data()
  ) {
    self.outcome = outcome
    self.started = started
    self.exitStatus = exitStatus
    self.exitedNormally = exitedNormally
    self.stdout = stdout
    self.stderr = stderr
    self.terminationRequested = terminationRequested
    self.killRequested = killRequested
    self.reaped = reaped
    failureStandardError =
      retainedFailureStandardError.isEmpty
      ? nil : BoundedCommandFailureOutputBuffer(retainedFailureStandardError)
  }

  package var succeeded: Bool {
    outcome == .exited && exitStatus == 0 && exitedNormally && started && reaped
  }

  /// Synchronously borrows explicitly retained failure stderr exactly once.
  /// Bytes are logically reset and released after `body` returns; Swift's
  /// allocator does not provide a cryptographic zeroization guarantee.
  package func consumeRetainedFailureStandardError(
    _ body: (UnsafeRawBufferPointer) -> Void
  ) {
    failureStandardError?.consume(body)
  }

  package static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.outcome == rhs.outcome
      && lhs.started == rhs.started
      && lhs.exitStatus == rhs.exitStatus
      && lhs.exitedNormally == rhs.exitedNormally
      && lhs.stdout == rhs.stdout
      && lhs.stderr == rhs.stderr
      && lhs.terminationRequested == rhs.terminationRequested
      && lhs.killRequested == rhs.killRequested
      && lhs.reaped == rhs.reaped
  }

  static func immediate(_ outcome: BoundedCommandOutcome) -> Self {
    Self(
      outcome: outcome,
      started: false,
      exitStatus: nil,
      exitedNormally: false,
      stdout: Data(),
      stderr: Data(),
      terminationRequested: false,
      killRequested: false,
      reaped: false
    )
  }
}

package struct BoundedCommandRunner: Sendable {
  package init() {}

  package func run(_ request: BoundedCommandRequest) async -> BoundedCommandResult {
    guard request.isValid else { return .immediate(.invalidRequest) }
    guard !Task.isCancelled else { return .immediate(.cancelled) }
    let execution = BoundedCommandExecution(request: request)
    execution.start()
    return await withTaskCancellationHandler {
      await execution.result()
    } onCancel: {
      execution.cancel()
    }
  }
}
