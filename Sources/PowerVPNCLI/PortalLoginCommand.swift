import Foundation
import PowerVPNPortal

enum PortalLoginCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String { "usage: powervpn login" }
}

struct PortalLoginCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

typealias PortalLoginRuntimeOperation = @Sendable () async -> PortalLoginReport
func runPortalLoginCommand(
  _ arguments: [String],
  runtime: @escaping PortalLoginRuntimeOperation = {
    await PortalLoginRuntime.runCurrentMachine()
  },
  signalMonitorFactory: CLISignalMonitorFactory = {
    DarwinCLISignalMonitor()
  }
) async throws -> PortalLoginCommandResult {
  guard arguments == ["login"] else {
    throw PortalLoginCommandError.invalidArguments
  }

  let cancellation = CLITaskCancellation<PortalLoginReport>()
  let signalMonitor = signalMonitorFactory()
  signalMonitor.start { cancellation.request() }
  let task = Task { await runtime() }
  cancellation.install(task)
  let report = await task.value
  cancellation.clear()
  signalMonitor.stop()

  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  let data = try encoder.encode(report)
  return PortalLoginCommandResult(
    standardOutput: String(decoding: data, as: UTF8.self),
    exitCode: report.transactionAccepted ? 0 : 2
  )
}
