import Foundation

package protocol BoundedVendorHelperGenerationObserving: Sendable {
  func observe() async -> VendorHelperGenerationSnapshot
}

/// Reads the fixed charon launchd service through the shared bounded command
/// runner. Failures, cancellation, timeouts, oversized output, and malformed
/// output all collapse to the value-free unavailable snapshot.
package struct InstalledBoundedVendorHelperGenerationObserver:
  BoundedVendorHelperGenerationObserving
{
  private let runner: any NetworkCleanupCommandRunning

  package init() {
    runner = InstalledNetworkCleanupCommandRunner()
  }

  init(runner: any NetworkCleanupCommandRunning) {
    self.runner = runner
  }

  package func observe() async -> VendorHelperGenerationSnapshot {
    let result = await runner.run(.helperGeneration)
    guard result.succeeded,
      !result.stdout.contains(0),
      let output = String(data: result.stdout, encoding: .utf8)
    else { return .unavailable }
    let snapshot = LaunchdVendorHelperSnapshotParser.parse(output)
    return snapshot.exactInactive || snapshot.exactRunning ? snapshot : .unavailable
  }
}
