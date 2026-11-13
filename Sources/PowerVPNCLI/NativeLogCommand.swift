import Foundation
import PowerVPNCore
import PowerVPNProduct

/// `powervpn native log [lines]`: recent native-backend diagnostics without root.
///
/// The root helper's log stays root-only (0600 in a 0700 directory); the helper
/// returns its newest sanitized lines over the owner-only control socket. The
/// per-attempt timings are the user's own file. Both were sanitized when
/// written (NativeLogSanitizer), and are sanitized again here.
func runNativeLogCommand(
  _ arguments: [String],
  helper: String = NativeHelperPaths.control,
  attemptLog: NativeRotatingLog = NativeAttemptLog.standard()
) -> UserProductCommandResult {
  let usage = "usage: powervpn native log [lines]"
  guard arguments.count <= 3, arguments.first == "native", arguments.dropFirst().first == "log"
  else { return .failure(usage, exitCode: 64, next: nil) }
  var count = 60
  if arguments.count == 3 {
    guard let value = Int(arguments[2]), (1...NativeHelperRequest.maximumLogLines).contains(value)
    else {
      return .failure(
        usage + " (1-\(NativeHelperRequest.maximumLogLines))", exitCode: 64, next: nil)
    }
    count = value
  }
  var output = "== powervpn attempts (\(attemptLog.path)) ==\n"
  let attempts = attemptLog.tail(lines: count)
  output += attempts.isEmpty ? "(none yet)\n" : attempts.map(show).joined(separator: "\n") + "\n"

  output += "== root helper and charon log (via the helper) ==\n"
  let reply = try? NativeHelperClient.send(
    .init(op: .logTail, lines: count), socketPath: helper, timeoutSeconds: 10,
    replyLimit: 131_072)
  var exitCode: Int32 = 0
  var next: String?
  if let reply, reply.ok, let lines = reply.logLines {
    output += lines.isEmpty ? "(empty)\n" : lines.map(show).joined(separator: "\n") + "\n"
  } else if (try? NativeHelperClient.send(.init(op: .status), socketPath: helper)) != nil {
    output += "(this helper build predates log access)\n"
    next = "reinstall the native backend to enable it: powervpn native status"
    exitCode = 1
  } else {
    output += "(the root helper is not reachable)\n"
    next = "powervpn native status"
    exitCode = 1
  }
  return UserProductCommandResult(
    standardOutput: output, standardError: next.map { "next: \($0)\n" } ?? "",
    exitCode: exitCode)
}

private func show(_ line: String) -> String {
  NativeLogSanitizer.sanitize(line, limit: 600)
}
