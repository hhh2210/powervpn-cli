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

package struct BoundedCommandRequest: Equatable, Sendable {
  package let executable: String
  package let arguments: [String]
  package let timeoutMilliseconds: Int
  package let stdoutLimitBytes: Int
  package let stderrLimitBytes: Int

  package init(
    executable: String,
    arguments: [String],
    timeoutMilliseconds: Int,
    stdoutLimitBytes: Int,
    stderrLimitBytes: Int
  ) {
    self.executable = executable
    self.arguments = arguments
    self.timeoutMilliseconds = timeoutMilliseconds
    self.stdoutLimitBytes = stdoutLimitBytes
    self.stderrLimitBytes = stderrLimitBytes
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
      && (1...60_000).contains(timeoutMilliseconds)
      && (1...16_777_216).contains(stdoutLimitBytes)
      && (1...16_777_216).contains(stderrLimitBytes)
  }

  private static let forbiddenExecutableNames: Set<String> = [
    "bash", "csh", "dash", "env", "fish", "ksh", "sh", "tcsh", "zsh",
  ]
}

package struct BoundedCommandResult: Equatable, Sendable {
  package let outcome: BoundedCommandOutcome
  package let started: Bool
  package let exitStatus: Int32?
  package let stdout: Data
  package let stderr: Data
  package let terminationRequested: Bool
  package let killRequested: Bool
  package let reaped: Bool

  package var succeeded: Bool {
    outcome == .exited && exitStatus == 0 && started && reaped
  }

  static func immediate(_ outcome: BoundedCommandOutcome) -> Self {
    Self(
      outcome: outcome,
      started: false,
      exitStatus: nil,
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
