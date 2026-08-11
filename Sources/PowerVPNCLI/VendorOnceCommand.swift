import Foundation
import PowerVPNProduct

enum VendorOnceCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String { "usage: powervpn vendor-once begin --json" }
}

enum VendorOnceBeginOutcome: String, Encodable, Equatable, Sendable {
  case armed
  case cursorRejected = "cursor_rejected"
}

struct VendorOnceBeginReport: Encodable, Equatable, Sendable {
  let schemaVersion = 1
  let outcome: VendorOnceBeginOutcome
  let onboardingMode = "vendor_once"
  let cursorPersisted: Bool
  let containsSecrets = false
  let serverContactRequested = false
  let helperMutationRequested = false
}

struct VendorOnceCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

typealias VendorOnceBeginOperation = @Sendable () throws -> Void

func runVendorOnceCommand(
  _ arguments: [String],
  begin: @escaping VendorOnceBeginOperation = {
    _ = try VendorAppOnboardingCursor.captureAndPersistInstalledSource()
  }
) throws -> VendorOnceCommandResult {
  guard arguments == ["vendor-once", "begin", "--json"] else {
    throw VendorOnceCommandError.invalidArguments
  }

  let report: VendorOnceBeginReport
  let exitCode: Int32
  do {
    try begin()
    report = VendorOnceBeginReport(
      outcome: .armed,
      cursorPersisted: true
    )
    exitCode = 0
  } catch {
    report = VendorOnceBeginReport(
      outcome: .cursorRejected,
      cursorPersisted: false
    )
    exitCode = 69
  }

  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  return VendorOnceCommandResult(
    standardOutput: String(decoding: try encoder.encode(report), as: UTF8.self),
    exitCode: exitCode
  )
}
