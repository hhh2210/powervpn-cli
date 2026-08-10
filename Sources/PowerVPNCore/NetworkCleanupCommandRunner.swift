import Foundation

enum NetworkCleanupCommand: CaseIterable, Hashable, Sendable {
  case helperGeneration
  case surgeProcesses
  case defaultRoute
  case dns
  case interfaces
  case ipv4Routes
  case ipv6Routes

  var request: BoundedCommandRequest {
    let executable: String
    let arguments: [String]
    let stdoutLimit: Int
    switch self {
    case .helperGeneration:
      executable = "/bin/launchctl"
      arguments = ["print", LaunchdVendorHelperGenerationObserver.helperLabel]
      stdoutLimit = 1_048_576
    case .surgeProcesses:
      executable = "/bin/ps"
      arguments = ["-axo", "pid=,lstart=,command="]
      stdoutLimit = 8_388_608
    case .defaultRoute:
      executable = "/sbin/route"
      arguments = ["-n", "get", "default"]
      stdoutLimit = 65_536
    case .dns:
      executable = "/usr/sbin/scutil"
      arguments = ["--dns"]
      stdoutLimit = 1_048_576
    case .interfaces:
      executable = "/sbin/ifconfig"
      arguments = ["-a"]
      stdoutLimit = 4_194_304
    case .ipv4Routes:
      executable = "/usr/sbin/netstat"
      arguments = ["-rn", "-f", "inet"]
      stdoutLimit = 8_388_608
    case .ipv6Routes:
      executable = "/usr/sbin/netstat"
      arguments = ["-rn", "-f", "inet6"]
      stdoutLimit = 8_388_608
    }
    return BoundedCommandRequest(
      executable: executable,
      arguments: arguments,
      timeoutMilliseconds: 2_000,
      stdoutLimitBytes: stdoutLimit,
      stderrLimitBytes: 65_536
    )
  }
}

protocol NetworkCleanupCommandRunning: Sendable {
  func run(_ command: NetworkCleanupCommand) async -> BoundedCommandResult
}

struct InstalledNetworkCleanupCommandRunner: NetworkCleanupCommandRunning {
  private let runner = BoundedCommandRunner()

  func run(_ command: NetworkCleanupCommand) async -> BoundedCommandResult {
    await runner.run(command.request)
  }
}

enum NetworkCleanupCommandOutput {
  static func state(_ result: BoundedCommandResult) -> NetworkCleanupObservationState {
    switch result.outcome {
    case .stdoutLimitExceeded, .stderrLimitExceeded: return .outputTooLarge
    case .exited where result.exitStatus == 0: return .observed
    default: return .commandFailed
    }
  }
}
