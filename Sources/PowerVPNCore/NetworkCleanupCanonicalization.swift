import CryptoKit
import Foundation

enum NetworkCleanupCanonicalizationError: Error, Equatable, Sendable {
  case invalidUTF8
  case invalidShape
  case duplicateValue
  case emptyInventory
}

enum NetworkCleanupDigest {
  static func sha256(domain: String, records: [String]) -> String {
    var hasher = SHA256()
    hasher.update(data: Data("powervpn.network-cleanup.v1\0\(domain)\0".utf8))
    for record in records {
      hasher.update(data: Data(record.utf8))
      hasher.update(data: Data([0x0a]))
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
  }

}

enum NetworkCleanupText {
  static func lines(_ data: Data) throws -> [String] {
    guard !data.contains(0), let text = String(data: data, encoding: .utf8) else {
      throw NetworkCleanupCanonicalizationError.invalidUTF8
    }
    return text.replacingOccurrences(of: "\r\n", with: "\n")
      .replacingOccurrences(of: "\r", with: "\n")
      .split(separator: "\n", omittingEmptySubsequences: false)
      .map(String.init)
  }

  static func normalizedWhitespace(_ line: String) -> String {
    line.split(whereSeparator: \Character.isWhitespace).joined(separator: " ")
  }
}

enum NetworkDefaultRouteCanonicalizer {
  private static let required = ["destination", "interface", "flags"]
  private static let optional = ["mask", "gateway"]

  static func canonicalize(_ data: Data) throws -> NetworkCleanupFingerprint {
    var values: [String: String] = [:]
    let accepted = Set(required + optional)
    for rawLine in try NetworkCleanupText.lines(data) {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      guard !line.isEmpty, let colon = line.firstIndex(of: ":") else { continue }
      let key = line[..<colon].trimmingCharacters(in: .whitespaces)
      guard accepted.contains(key) else { continue }
      let value = NetworkCleanupText.normalizedWhitespace(String(line[line.index(after: colon)...]))
      guard !value.isEmpty else { throw NetworkCleanupCanonicalizationError.invalidShape }
      guard values.updateValue(value, forKey: key) == nil else {
        throw NetworkCleanupCanonicalizationError.duplicateValue
      }
    }
    guard required.allSatisfy({ values[$0] != nil }) else {
      throw NetworkCleanupCanonicalizationError.invalidShape
    }
    if values["gateway"] == nil {
      guard let interface = values["interface"], isExactUtunInterface(interface) else {
        throw NetworkCleanupCanonicalizationError.invalidShape
      }
    }
    let records = (required + optional).compactMap { key in
      values[key].map { "\(key)=\($0)" }
    }
    return .observed(
      count: 1,
      sha256: NetworkCleanupDigest.sha256(domain: "default-route", records: records)
    )
  }

  private static func isExactUtunInterface(_ value: String) -> Bool {
    guard value.hasPrefix("utun") else { return false }
    let suffix = value.dropFirst(4).utf8
    return !suffix.isEmpty && suffix.allSatisfy { (0x30...0x39).contains($0) }
  }
}

enum NetworkDNSCanonicalizer {
  static func canonicalize(_ data: Data) throws -> NetworkCleanupFingerprint {
    let normalized = try NetworkCleanupText.lines(data).map {
      NetworkCleanupText.normalizedWhitespace($0)
    }
    var records: [String] = []
    for line in normalized where !line.isEmpty {
      records.append(line)
    }
    guard !records.isEmpty else { throw NetworkCleanupCanonicalizationError.emptyInventory }
    let noConfiguration = records == ["No DNS configuration available"]
    if noConfiguration {
      return .observed(
        count: 0,
        sha256: NetworkCleanupDigest.sha256(domain: "dns", records: records)
      )
    }
    var sawSection = false
    var sectionHasResolver = false
    var nextResolver = 1
    var resolverCount = 0
    for line in records {
      if line.hasPrefix("DNS configuration") {
        guard !sawSection || sectionHasResolver else {
          throw NetworkCleanupCanonicalizationError.invalidShape
        }
        sawSection = true
        sectionHasResolver = false
        nextResolver = 1
      } else if line.hasPrefix("resolver #") {
        guard sawSection,
          line.dropFirst("resolver #".count) == Substring(String(nextResolver))
        else { throw NetworkCleanupCanonicalizationError.invalidShape }
        resolverCount += 1
        sectionHasResolver = true
        nextResolver += 1
      }
    }
    guard resolverCount > 0, sectionHasResolver else {
      throw NetworkCleanupCanonicalizationError.invalidShape
    }
    return .observed(
      count: resolverCount,
      sha256: NetworkCleanupDigest.sha256(domain: "dns", records: records)
    )
  }
}

enum NetworkInterfaceCanonicalizer {
  static func canonicalize(
    _ data: Data,
    window: NetworkCleanupCaptureWindow
  ) throws -> NetworkCleanupInterfaceSnapshot {
    var blocks: [String: [String]] = [:]
    var current: String?
    for rawLine in try NetworkCleanupText.lines(data) where !rawLine.isEmpty {
      if !rawLine.first!.isWhitespace {
        guard let colon = rawLine.firstIndex(of: ":") else {
          throw NetworkCleanupCanonicalizationError.invalidShape
        }
        let name = String(rawLine[..<colon])
        guard validName(name), blocks[name] == nil else {
          throw NetworkCleanupCanonicalizationError.duplicateValue
        }
        current = name
        blocks[name] = [NetworkCleanupText.normalizedWhitespace(rawLine)]
      } else {
        guard let current else { throw NetworkCleanupCanonicalizationError.invalidShape }
        let line = NetworkCleanupText.normalizedWhitespace(rawLine)
        if !line.isEmpty { blocks[current, default: []].append(line) }
      }
    }
    guard !blocks.isEmpty else { throw NetworkCleanupCanonicalizationError.emptyInventory }
    let records = blocks.keys.sorted().flatMap { name in
      ["interface=\(name)"] + (blocks[name] ?? [])
    }
    let utunNames = blocks.keys.filter(Self.isUtunName).sorted()
    return NetworkCleanupInterfaceSnapshot(
      inventory: .observed(
        count: blocks.count,
        sha256: NetworkCleanupDigest.sha256(domain: "interfaces", records: records)
      ),
      utunCount: utunNames.count,
      utunTokens: Set(utunNames.map(window.interfaceToken))
    )
  }

  private static func validName(_ value: String) -> Bool {
    guard let first = value.utf8.first, (65...90).contains(first) || (97...122).contains(first)
    else { return false }
    return value.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        || $0 == 0x2e || $0 == 0x3a || $0 == 0x5f || $0 == 0x2d
    }
  }

  private static func isUtunName(_ value: String) -> Bool {
    guard value.hasPrefix("utun") else { return false }
    let suffix = value.dropFirst(4)
    return !suffix.isEmpty && suffix.utf8.allSatisfy { (0x30...0x39).contains($0) }
  }
}
