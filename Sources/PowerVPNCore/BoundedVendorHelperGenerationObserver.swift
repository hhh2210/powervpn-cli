import Foundation

package protocol BoundedVendorHelperGenerationObserving: Sendable {
  func observe(timeoutMilliseconds: Int) async -> VendorHelperGenerationSnapshot
}

extension BoundedVendorHelperGenerationObserving {
  package func observe() async -> VendorHelperGenerationSnapshot {
    await observe(timeoutMilliseconds: 2_000)
  }
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

  package func observe(
    timeoutMilliseconds: Int
  ) async -> VendorHelperGenerationSnapshot {
    precondition((1...2_000).contains(timeoutMilliseconds))
    let result = await runner.run(
      .helperGeneration,
      timeoutMilliseconds: timeoutMilliseconds
    )
    guard result.succeeded,
      !result.stdout.contains(0),
      let output = String(data: result.stdout, encoding: .utf8)
    else { return .unavailable }
    let snapshot = LaunchdVendorHelperSnapshotParser.parse(output)
    return snapshot.exactInactive || snapshot.exactRunning ? snapshot : .unavailable
  }
}
