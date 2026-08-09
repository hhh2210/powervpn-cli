import Foundation
import PowerVPNCore

enum VendorXPCCommandError: Error, CustomStringConvertible {
  case invalidArguments

  var description: String {
    "usage: powervpn xpc get-version [--timeout-ms N] [--json]"
  }
}

func runVendorXPCCommand(_ arguments: [String], json: Bool) async throws {
  let timeout = try parseVendorXPCTimeout(arguments)
  let report = await VendorXPCProbe().getVersion(timeoutMilliseconds: timeout)
  if json {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(report)
    print(String(decoding: data, as: UTF8.self))
  } else {
    print("vendor charon get_version: \(report.status.rawValue)")
    print("transport: \(report.transportOutcome?.rawValue ?? "not_run")")
    print("generation: \(report.helperGenerationRelation.rawValue)")
    print("exact reply: \(report.exactReplySchema ? "yes" : "no")")
    print(
      "connection cancel: \(report.connectionCancelRequested ? "requested" : "not_requested")"
    )
  }
  if !report.transactionAccepted {
    Foundation.exit(2)
  }
}

private func parseVendorXPCTimeout(_ arguments: [String]) throws -> Int {
  guard arguments.count >= 2,
    arguments[0] == "xpc",
    arguments[1] == "get-version"
  else {
    throw VendorXPCCommandError.invalidArguments
  }

  var index = 2
  var timeout = RawVendorXPCTransport.defaultTimeoutMilliseconds
  if arguments.indices.contains(index), arguments[index] == "--timeout-ms" {
    guard arguments.indices.contains(index + 1),
      let parsed = Int(arguments[index + 1]),
      RawVendorXPCTransport.validTimeoutMilliseconds.contains(parsed)
    else {
      throw VendorXPCCommandError.invalidArguments
    }
    timeout = parsed
    index += 2
  }
  if arguments.indices.contains(index), arguments[index] == "--json" {
    index += 1
  }
  guard index == arguments.count else {
    throw VendorXPCCommandError.invalidArguments
  }
  return timeout
}
