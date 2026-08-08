import Foundation
import PowerVPNCore

func runVICICommand(_ arguments: [String], json: Bool) throws {
  guard arguments.count >= 2 else {
    throw VICICLIError.invalidArguments(usage)
  }
  let options = try parseVICIOptions(Array(arguments.dropFirst(2)))
  switch arguments[1] {
  case "version":
    let report = try VICIRuntimeProbe.version(
      socketPath: options.socketPath,
      timeoutMilliseconds: options.timeoutMilliseconds
    )
    if json {
      printVICIJSON(report)
    } else {
      print("VICI version: ready")
      print("response keys: \(report.responseKeyNames.joined(separator: ", "))")
      print(
        "wire bytes: write=\(report.trace.requestWireBytes) read=\(report.trace.responseWireBytes)"
      )
    }
  case "cp7a-smoke":
    let report = try VICIRuntimeProbe.smoke(
      socketPath: options.socketPath,
      timeoutMilliseconds: options.timeoutMilliseconds
    )
    if json {
      printVICIJSON(report)
    } else {
      print("VICI CP7A synthetic runtime: PASS")
      print(
        "load/list/unload: \(report.listAfterLoad.syntheticConnectionMatches)/\(report.listAfterUnload.syntheticConnectionMatches)"
      )
      print("credentials/initiate/install: none")
    }
  default:
    throw VICICLIError.invalidArguments(usage)
  }
}

private struct VICIOptions {
  let socketPath: String
  let timeoutMilliseconds: Int
}

private enum VICICLIError: Error, CustomStringConvertible {
  case invalidArguments(String)

  var description: String {
    switch self {
    case .invalidArguments(let message): message
    }
  }
}

private let usage = """
  usage: powervpn vici <version|cp7a-smoke> --socket <path> [--timeout-ms N] [--json]
  """

private func parseVICIOptions(_ arguments: [String]) throws -> VICIOptions {
  var socketPath: String?
  var timeoutMilliseconds = 2_000
  var sawTimeout = false
  var index = 0

  while index < arguments.count {
    switch arguments[index] {
    case "--socket":
      guard socketPath == nil, arguments.indices.contains(index + 1),
        !arguments[index + 1].hasPrefix("--")
      else {
        throw VICICLIError.invalidArguments(usage)
      }
      socketPath = arguments[index + 1]
      index += 2
    case "--timeout-ms":
      guard !sawTimeout, arguments.indices.contains(index + 1),
        let value = Int(arguments[index + 1]), (1...60_000).contains(value)
      else {
        throw VICICLIError.invalidArguments(usage)
      }
      timeoutMilliseconds = value
      sawTimeout = true
      index += 2
    case "--json":
      index += 1
    default:
      throw VICICLIError.invalidArguments(usage)
    }
  }

  guard let socketPath, !socketPath.isEmpty else {
    throw VICICLIError.invalidArguments(usage)
  }
  return VICIOptions(socketPath: socketPath, timeoutMilliseconds: timeoutMilliseconds)
}

private func printVICIJSON<T: Encodable>(_ value: T) {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  let data = try! encoder.encode(value)
  print(String(decoding: data, as: UTF8.self))
}
