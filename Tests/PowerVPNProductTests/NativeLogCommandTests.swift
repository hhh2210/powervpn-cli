import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore
@testable import PowerVPNProduct

@Suite struct NativeLogCommandTests {
  private func attemptLog() -> NativeRotatingLog {
    NativeRotatingLog(path: NSTemporaryDirectory() + "powervpn-attempts-" + UUID().uuidString)
  }

  @Test(arguments: [
    ["native", "log", "0"], ["native", "log", "201"], ["native", "log", "x"],
    ["native", "log", "1", "2"],
  ])
  func rejectsBadLineCounts(arguments: [String]) {
    let result = runNativeLogCommand(
      arguments, helper: "/tmp/powervpn-absent-\(UUID().uuidString)", attemptLog: attemptLog())
    #expect(result.exitCode == 64)
  }

  /// No root, no live helper: the user's own attempt lines are shown (and
  /// sanitized again on the way out) even when the helper is unreachable.
  @Test func showsOwnAttemptsAndNamesAnUnreachableHelper() throws {
    let log = attemptLog()
    defer { try? FileManager.default.removeItem(atPath: log.path) }
    log.append("2026-11-13T05:10:00Z ab12cd34 attempt=1 phase=child outcome=failed ms=1312")
    log.append("2026-11-13T05:10:00Z ab12cd34 for: 'Q7zK.session-42'")
    let result = runNativeLogCommand(
      ["native", "log", "5"], helper: "/tmp/powervpn-absent-\(UUID().uuidString)",
      attemptLog: log)
    #expect(result.exitCode == 1)
    #expect(result.standardOutput.contains("attempt=1 phase=child outcome=failed ms=1312"))
    #expect(!result.standardOutput.contains("Q7zK"))
    #expect(result.standardOutput.contains("the root helper is not reachable"))
    #expect(result.standardError.contains("next: powervpn native status"))
  }
}
