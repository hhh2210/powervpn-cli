import Foundation

enum LegacyNetworkCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String {
    "usage: powervpn <probe|diagnose> [--json]"
  }
}

struct LegacyNetworkCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

private struct LegacyNetworkBlockedReport: Encodable {
  let schemaVersion = 1
  let outcome = "explicit_m2_approval_required"
  let networkRequested = false
  let helperMutationRequested = false
  let containsSecrets = false
}

func runLegacyNetworkCommand(
  _ arguments: [String]
) throws -> LegacyNetworkCommandResult {
  guard
    arguments == ["probe"] || arguments == ["probe", "--json"]
      || arguments == ["diagnose"] || arguments == ["diagnose", "--json"]
  else { throw LegacyNetworkCommandError.invalidArguments }

  if arguments.last == "--json" {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return LegacyNetworkCommandResult(
      standardOutput: String(
        decoding: try encoder.encode(LegacyNetworkBlockedReport()), as: UTF8.self),
      exitCode: 69
    )
  }
  return LegacyNetworkCommandResult(
    standardOutput:
      "blocked: use the approval-gated m2 connect-once transaction; no network request was sent",
    exitCode: 69
  )
}
