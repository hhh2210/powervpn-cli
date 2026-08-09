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

typealias PortalLoginRuntimeOperation = () async -> PortalLoginReport

func runPortalLoginCommand(
  _ arguments: [String],
  runtime: PortalLoginRuntimeOperation = {
    await PortalLoginRuntime.runCurrentMachine()
  }
) async throws -> PortalLoginCommandResult {
  guard arguments == ["login"] else {
    throw PortalLoginCommandError.invalidArguments
  }

  let report = await runtime()
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  let data = try encoder.encode(report)
  return PortalLoginCommandResult(
    standardOutput: String(decoding: data, as: UTF8.self),
    exitCode: report.transactionAccepted ? 0 : 2
  )
}
