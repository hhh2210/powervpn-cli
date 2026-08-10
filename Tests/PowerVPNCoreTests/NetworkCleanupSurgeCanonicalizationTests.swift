import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupSurgeCanonicalizationTests {
  @Test func processOrderIsCanonicalAndOnlyExactSurgeImagesCount() throws {
    let rows = [
      surgeRow(pid: 100, executable: "/Applications/Surge.app/Contents/MacOS/Surge"),
      surgeRow(
        pid: 101,
        executable:
          "/Applications/Surge.app/Contents/PlugIns/Surge.appex/Contents/MacOS/com.nssurge.surge-mac.ne"
      ),
      surgeRow(
        pid: 102,
        executable: "/Library/PrivilegedHelperTools/com.nssurge.surge-mac.helper"
      ),
      surgeRow(pid: 103, executable: "/tmp/not-Surge"),
      surgeRow(pid: 104, executable: "/tmp/Surge"),
    ]
    let first = try canonical(rows)
    let reversed = try canonical(rows.reversed())
    #expect(first == reversed)
    #expect(first.fingerprint.itemCount == 3)
    #expect(first.mainProcessCount == 1)
    #expect(first.extensionProcessCount == 1)
    #expect(first.helperProcessCount == 1)
  }

  @Test func pidStartAndCommandChangesAlterIdentityWithoutRetainingCommand() throws {
    let marker = "sensitive-command-marker"
    let base = try canonical([
      surgeRow(pid: 100, executable: "/Applications/Surge.app/Contents/MacOS/Surge")
    ])
    let pidChanged = try canonical([
      surgeRow(pid: 200, executable: "/Applications/Surge.app/Contents/MacOS/Surge")
    ])
    let commandChanged = try canonical([
      surgeRow(
        pid: 100,
        executable: "/Applications/Surge.app/Contents/MacOS/Surge \(marker)"
      )
    ])
    #expect(base != pidChanged)
    #expect(base != commandChanged)
    #expect(!String(describing: commandChanged).contains(marker))
  }

  @Test func duplicatePIDAndMalformedRowsFailClosed() {
    let row = surgeRow(pid: 100, executable: "Surge")
    #expect(throws: NetworkCleanupCanonicalizationError.duplicateValue) {
      try canonical([row, row])
    }
    #expect(throws: NetworkCleanupCanonicalizationError.invalidShape) {
      try canonical(["100 malformed Surge"])
    }
  }
}

private func canonical<S: Sequence>(_ rows: S) throws -> NetworkCleanupSurgeSnapshot
where S.Element == String {
  try NetworkSurgeProcessCanonicalizer.canonicalize(
    Data((rows.joined(separator: "\n") + "\n").utf8)
  )
}

private func surgeRow(pid: Int, executable: String) -> String {
  "\(pid) Tue Aug 11 12:34:56 2026 \(executable)"
}
