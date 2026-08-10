import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupVendorProcessTests {
  @Test func canonicalizationIsOrderedWindowScopedAndValueFree() throws {
    let rows = [
      "20 Tue Aug 11 12:34:56 2026 /Applications/PowerVPN.app/Contents/MacOS/PowerVPN",
      "21 Tue Aug 11 12:34:57 2026 /Library/PrivilegedHelperTools/com.leadsec.charon-xpc --mode vpn",
      "22 Tue Aug 11 12:34:58 2026 /Library/PrivilegedHelperTools/com.leadsec.ipsec-xpc",
      "23 Tue Aug 11 12:34:59 2026 /Applications/PowerVPN.app/Contents/Library/LaunchServices/com.leadsec.sh-xpc",
      "24 Tue Aug 11 12:35:00 2026 /usr/bin/unrelated --secret ignored",
    ]
    let firstWindow = NetworkCleanupCaptureWindow(keyData: Data(repeating: 1, count: 32))
    let secondWindow = NetworkCleanupCaptureWindow(keyData: Data(repeating: 2, count: 32))
    let first = try canonical(rows, window: firstWindow)
    let reordered = try canonical(rows.reversed(), window: firstWindow)
    let differentWindow = try canonical(rows, window: secondWindow)

    #expect(first == reordered)
    #expect(first.fingerprint.itemCount == 4)
    #expect(first.officialGUIProcessCount == 1)
    #expect(first.charonProcessCount == 1)
    #expect(first.ipsecProcessCount == 1)
    #expect(first.shellProcessCount == 1)
    #expect(first.identityTokens.count == 4)
    #expect(first.fingerprint != differentWindow.fingerprint)
    #expect(!String(describing: first).contains("--secret"))
    #expect(!String(describing: first).contains("/Applications/PowerVPN"))
  }

  @Test func pidStartAndCommandAllBindTheIdentity() throws {
    let window = NetworkCleanupCaptureWindow(keyData: Data(repeating: 3, count: 32))
    let base = "21 Tue Aug 11 12:34:57 2026 /x/com.leadsec.charon-xpc --mode vpn"
    let changedPID = base.replacingOccurrences(of: "21 ", with: "25 ")
    let changedStart = base.replacingOccurrences(of: "12:34:57", with: "12:34:58")
    let changedCommand = base.replacingOccurrences(of: "--mode vpn", with: "--mode other")

    let baseline = try canonical([base], window: window)
    let pidResult = try canonical([changedPID], window: window)
    let startResult = try canonical([changedStart], window: window)
    let commandResult = try canonical([changedCommand], window: window)
    #expect(baseline.identityTokens != pidResult.identityTokens)
    #expect(baseline.identityTokens != startResult.identityTokens)
    #expect(baseline.identityTokens != commandResult.identityTokens)
  }

  @Test func generationConsistencyRequiresColdAbsenceOrOneRunningCharon() throws {
    let window = NetworkCleanupCaptureWindow(keyData: Data(repeating: 4, count: 32))
    let unrelated = try canonical(
      ["30 Tue Aug 11 12:34:56 2026 /usr/bin/unrelated"],
      window: window
    )
    let charon = try canonical(
      ["31 Tue Aug 11 12:34:56 2026 /x/com.leadsec.charon-xpc"],
      window: window
    )
    let cold = generation(running: false)
    let active = generation(running: true)

    #expect(unrelated.isConsistent(with: cold))
    #expect(!unrelated.isConsistent(with: active))
    #expect(charon.isConsistent(with: active))
    #expect(!charon.isConsistent(with: cold))
  }

  @Test func malformedOrDuplicateProcessInventoryFailsClosed() {
    let window = NetworkCleanupCaptureWindow()
    for rows in [
      ["1 Bogus Aug 11 12:34:56 2026 /usr/bin/a"],
      [
        "1 Tue Aug 11 12:34:56 2026 /usr/bin/a",
        "1 Tue Aug 11 12:34:57 2026 /usr/bin/b",
      ],
      [],
    ] {
      #expect(throws: (any Error).self) {
        try canonical(rows, window: window)
      }
    }
  }
}

private func canonical<S: Sequence>(
  _ rows: S,
  window: NetworkCleanupCaptureWindow
) throws -> NetworkCleanupVendorProcessSnapshot where S.Element == String {
  try NetworkVendorProcessCanonicalizer.canonicalize(
    Data((rows.joined(separator: "\n") + "\n").utf8),
    window: window
  )
}

private func generation(running: Bool) -> VendorHelperGenerationSnapshot {
  VendorHelperGenerationSnapshot(
    launchdObserved: true,
    running: running,
    inactiveConfirmed: !running,
    activeCount: running ? 1 : 0,
    pid: running ? 31 : nil,
    runs: running ? 11 : 10
  )
}
