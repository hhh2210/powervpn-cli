import Foundation
import Testing

@testable import PowerVPNCore

@Test func allowlistedLogReaderNeverReturnsUnmatchedSecretLines() throws {
  let url = FileManager.default.temporaryDirectory
    .appendingPathComponent("powervpn-log-\(UUID().uuidString).txt")
  defer { try? FileManager.default.removeItem(at: url) }
  let secret = "session=do-not-retain credential=do-not-retain"
  let log = """
    \(secret)
    loaded plugins: leadsecbridge charon nonce session=must-not-survive
    unrelated password=do-not-retain
    feature CUSTOM:kernel-ipsec in critical plugin 'leadsecbridge' failed to load
    """
  try Data(log.utf8).write(to: url)

  let filtered = AllowlistedLogReader.readLines(
    path: url.path,
    maximumBytes: UInt64(log.utf8.count),
    markers: VendorOracleAnalyzer.allowlistedLogMarkers,
    sanitizer: VendorOracleAnalyzer.sanitizeAllowlistedLogLine
  )

  #expect(filtered.contains("loaded plugins: leadsecbridge charon nonce"))
  #expect(filtered.contains("feature CUSTOM:kernel-ipsec"))
  #expect(!filtered.contains(secret))
  #expect(!filtered.contains("must-not-survive"))
  #expect(!filtered.contains("password=do-not-retain"))
}

@Test func allowlistedLogReaderDiscardsPartialFirstTailLine() throws {
  let url = FileManager.default.temporaryDirectory
    .appendingPathComponent("powervpn-tail-\(UUID().uuidString).txt")
  defer { try? FileManager.default.removeItem(at: url) }
  let prefix = "loaded plugins: leadsecbridge secret-fragment"
  let suffix = "loaded plugins: charon nonce\n"
  try Data("\(prefix)\n\(suffix)".utf8).write(to: url)

  let filtered = AllowlistedLogReader.readLines(
    path: url.path,
    maximumBytes: UInt64(suffix.utf8.count + 8),
    markers: ["loaded plugins:"],
    sanitizer: VendorOracleAnalyzer.sanitizeAllowlistedLogLine
  )

  #expect(filtered == "loaded plugins: charon nonce")
  #expect(!filtered.contains("secret-fragment"))
}

@Test func defaultLogSanitizerReturnsOnlyCanonicalMarkers() throws {
  let url = FileManager.default.temporaryDirectory
    .appendingPathComponent("powervpn-marker-\(UUID().uuidString).txt")
  defer { try? FileManager.default.removeItem(at: url) }
  let marker = "CHILD_SA established"
  let log = "\(marker) session=must-not-survive\n"
  try Data(log.utf8).write(to: url)

  let filtered = AllowlistedLogReader.readLines(
    path: url.path,
    maximumBytes: UInt64(log.utf8.count),
    markers: [marker]
  )

  #expect(filtered == marker)
  #expect(!filtered.contains("must-not-survive"))
}
