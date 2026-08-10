import Foundation
import PowerVPNProduct

enum ProductCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String {
    "usage: powervpn <doctor --json|helper status [--probe] --json|resources --json|snapshot --dry-run --json>"
  }
}

struct ProductCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

func runProductCommand(
  _ arguments: [String],
  runtime: ProductReadinessRuntime = ProductReadinessRuntime()
) async throws -> ProductCommandResult {
  switch arguments {
  case ["doctor", "--json"]:
    let report = runtime.doctor()
    return try result(report, exitCode: report.productState == .ready ? 0 : 2)
  case ["helper", "status", "--json"]:
    let report = runtime.helperStatus()
    return try result(report, exitCode: report.productState == .ready ? 0 : 2)
  case ["helper", "status", "--probe", "--json"]:
    let report = await runtime.helperStatusWithLiveProbe()
    return try result(report, exitCode: report.productState == .ready ? 0 : 2)
  case ["resources", "--json"]:
    let report = runtime.resources()
    return try result(report, exitCode: report.productState == .ready ? 0 : 69)
  case ["snapshot", "--dry-run", "--json"]:
    let report = runtime.snapshotDryRun()
    return try result(report, exitCode: report.snapshotComplete ? 0 : 69)
  default:
    throw ProductCommandError.invalidArguments
  }
}

private func result<T: Encodable>(
  _ report: T,
  exitCode: Int32
) throws -> ProductCommandResult {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  let data = try encoder.encode(report)
  return ProductCommandResult(
    standardOutput: String(decoding: data, as: UTF8.self),
    exitCode: exitCode
  )
}
