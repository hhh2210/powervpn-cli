import Foundation

enum NetworkSurgeProcessClass: String, Sendable {
  case main
  case networkExtension = "network-extension"
  case helper
}

enum NetworkSurgeProcessCanonicalizer {
  private static let helperPath =
    "/Library/PrivilegedHelperTools/com.nssurge.surge-mac.helper"
  private static let mainPath = "/Applications/Surge.app/Contents/MacOS/Surge"

  static func canonicalize(_ data: Data) throws -> NetworkCleanupSurgeSnapshot {
    var records: [String] = []
    var seenPIDs: Set<Int> = []
    var counts: [NetworkSurgeProcessClass: Int] = [:]
    for rawLine in try NetworkCleanupText.lines(data) {
      let fields = rawLine.split(whereSeparator: \Character.isWhitespace)
      guard !fields.isEmpty else { continue }
      guard fields.count >= 7, let pid = Int(fields[0]), pid > 0,
        validStartFields(fields[1...5])
      else { throw NetworkCleanupCanonicalizationError.invalidShape }
      guard seenPIDs.insert(pid).inserted else {
        throw NetworkCleanupCanonicalizationError.duplicateValue
      }
      let executable = String(fields[6])
      guard let processClass = classify(executable) else { continue }
      let start = fields[1...5].joined(separator: " ")
      let command = fields[6...].joined(separator: " ")
      let startHash = NetworkCleanupDigest.sha256(
        domain: "surge-process-start", records: [start])
      let commandHash = NetworkCleanupDigest.sha256(
        domain: "surge-process-command", records: [command])
      records.append("\(processClass.rawValue)\t\(pid)\t\(startHash)\t\(commandHash)")
      counts[processClass, default: 0] += 1
    }
    records.sort()
    return NetworkCleanupSurgeSnapshot(
      fingerprint: .observed(
        count: records.count,
        sha256: NetworkCleanupDigest.sha256(domain: "surge-processes", records: records)
      ),
      mainProcessCount: counts[.main, default: 0],
      extensionProcessCount: counts[.networkExtension, default: 0],
      helperProcessCount: counts[.helper, default: 0]
    )
  }

  private static func classify(_ executable: String) -> NetworkSurgeProcessClass? {
    if executable == "Surge" || executable == mainPath { return .main }
    if executable == "com.nssurge.surge-mac.ne"
      || executable.hasSuffix("/com.nssurge.surge-mac.ne")
    {
      return .networkExtension
    }
    return executable == helperPath ? .helper : nil
  }

  private static func validStartFields<C: Collection>(_ fields: C) -> Bool
  where C.Element == Substring {
    let values = Array(fields)
    guard values.count == 5,
      values[0].count == 3,
      values[1].count == 3,
      (1...2).contains(values[2].count),
      Int(values[2]) != nil,
      values[3].split(separator: ":").count == 3,
      values[4].count == 4,
      Int(values[4]) != nil
    else { return false }
    return true
  }
}
