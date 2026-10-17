import Darwin
import Foundation

public enum PowerVPNTargetsConfigurationError: Error, Equatable, Sendable {
  case missing
  case invalid
  case targetUnknown

  public var token: String {
    switch self {
    case .missing: "config_missing"
    case .invalid: "target_invalid"
    case .targetUnknown: "target_unknown"
    }
  }
}

public struct PowerVPNTargetConfiguration: Equatable, Sendable {
  public let host: String
  public let ipv4: UInt32
  public let user: String
  public let resourceDisplayName: String?

  fileprivate init(
    host: String,
    ipv4: UInt32,
    user: String,
    resourceDisplayName: String?
  ) {
    self.host = host
    self.ipv4 = ipv4
    self.user = user
    self.resourceDisplayName = resourceDisplayName
  }
}

public struct PowerVPNTargetsConfiguration: Equatable, Sendable {
  public static let path = "~/.config/powervpn/targets.json"

  public let portalOrigin: URL
  private let targets: [String: PowerVPNTargetConfiguration]

  public static func currentMachine() throws -> Self {
    let path = (Self.path as NSString).expandingTildeInPath
    return try read(path: path, owner: getuid())
  }

  public static func read(path: String, owner: uid_t = getuid()) throws -> Self {
    let data = try readProtectedFile(path: path, owner: owner)
    return try decode(data)
  }

  public static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= 64 * 1_024 else {
      throw PowerVPNTargetsConfigurationError.invalid
    }
    let decoded: FileSchema
    do {
      decoded = try JSONDecoder().decode(FileSchema.self, from: data)
    } catch {
      throw PowerVPNTargetsConfigurationError.invalid
    }
    guard let origin = validatedOrigin(decoded.portalOrigin), !decoded.targets.isEmpty else {
      throw PowerVPNTargetsConfigurationError.invalid
    }
    var validated: [String: PowerVPNTargetConfiguration] = [:]
    validated.reserveCapacity(decoded.targets.count)
    for (key, target) in decoded.targets {
      guard validKey(key), let ipv4 = parseIPv4(target.host), validUser(target.user),
        target.resourceDisplayName.map(validResourceDisplayName) ?? true
      else {
        throw PowerVPNTargetsConfigurationError.invalid
      }
      validated[key] = PowerVPNTargetConfiguration(
        host: target.host,
        ipv4: ipv4,
        user: target.user,
        resourceDisplayName: target.resourceDisplayName
      )
    }
    return Self(portalOrigin: origin, targets: validated)
  }

  public func target(named key: String) throws -> PowerVPNTargetConfiguration {
    guard Self.validKey(key) else { throw PowerVPNTargetsConfigurationError.invalid }
    guard let target = targets[key] else {
      throw PowerVPNTargetsConfigurationError.targetUnknown
    }
    return target
  }

  public var configuredTargetKeys: [String] { targets.keys.sorted() }

  public var productTargetsComplete: Bool {
    !targets.isEmpty && targets.values.allSatisfy { $0.resourceDisplayName != nil }
  }

  package var portalProfile: InstalledPortalProfile {
    InstalledPortalProfile(
      origin: portalOrigin,
      portalVersion: "2.0",
      selectionSemantics: .operatorApprovedFixedOrigin,
      vendorLanguageIndex: 0
    )
  }

  private struct FileSchema: Decodable {
    let portalOrigin: String
    let targets: [String: TargetSchema]

    init(from decoder: any Decoder) throws {
      let container = try decoder.container(keyedBy: ConfigurationCodingKey.self)
      guard Set(container.allKeys.map(\.stringValue)) == ["portalOrigin", "targets"] else {
        throw PowerVPNTargetsConfigurationError.invalid
      }
      portalOrigin = try container.decode(
        String.self,
        forKey: ConfigurationCodingKey("portalOrigin")
      )
      targets = try container.decode(
        [String: TargetSchema].self,
        forKey: ConfigurationCodingKey("targets")
      )
    }
  }

  private struct TargetSchema: Decodable {
    let host: String
    let user: String
    let resourceDisplayName: String?

    init(from decoder: any Decoder) throws {
      let container = try decoder.container(keyedBy: ConfigurationCodingKey.self)
      let keys = Set(container.allKeys.map(\.stringValue))
      guard keys == ["host", "user"] || keys == ["host", "user", "resource"] else {
        throw PowerVPNTargetsConfigurationError.invalid
      }
      host = try container.decode(String.self, forKey: ConfigurationCodingKey("host"))
      user = try container.decode(String.self, forKey: ConfigurationCodingKey("user"))
      resourceDisplayName = try container.decodeIfPresent(
        String.self,
        forKey: ConfigurationCodingKey("resource")
      )
    }
  }

  private static func validatedOrigin(_ text: String) -> URL? {
    guard let url = URL(string: text), url.absoluteString == text,
      url.scheme == "https", url.host != nil, url.port != nil,
      url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
      url.path.isEmpty
    else { return nil }
    return url
  }

  private static func validKey(_ value: String) -> Bool {
    (1...64).contains(value.utf8.count)
      && value.utf8.allSatisfy {
        (0x30...0x39).contains($0) || (0x41...0x5A).contains($0)
          || (0x61...0x7A).contains($0) || $0 == 0x2D || $0 == 0x5F
      }
  }

  private static func validUser(_ value: String) -> Bool {
    (1...64).contains(value.utf8.count)
      && value.utf8.allSatisfy {
        (0x30...0x39).contains($0) || (0x41...0x5A).contains($0)
          || (0x61...0x7A).contains($0) || $0 == 0x2D || $0 == 0x5F || $0 == 0x2E
      }
  }

  private static func validResourceDisplayName(_ value: String) -> Bool {
    (1...256).contains(value.utf8.count)
      && !value.unicodeScalars.contains {
        CharacterSet.controlCharacters.contains($0)
          || CharacterSet.newlines.contains($0)
      }
  }

  private static func parseIPv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var value: UInt32 = 0
    for part in parts {
      guard !part.isEmpty, part.count <= 3,
        part.count == 1 || part.first != "0",
        part.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
        let octet = UInt32(part), octet <= 255
      else { return nil }
      value = (value << 8) | octet
    }
    return value
  }

  private static func readProtectedFile(path: String, owner: uid_t) throws -> Data {
    var linkStat = stat()
    guard lstat(path, &linkStat) == 0 else {
      if errno == ENOENT { throw PowerVPNTargetsConfigurationError.missing }
      throw PowerVPNTargetsConfigurationError.invalid
    }
    guard linkStat.st_mode & S_IFMT == S_IFREG else {
      throw PowerVPNTargetsConfigurationError.invalid
    }
    let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw PowerVPNTargetsConfigurationError.invalid }
    defer { close(descriptor) }

    var opened = stat()
    guard fstat(descriptor, &opened) == 0,
      opened.st_mode & S_IFMT == S_IFREG,
      opened.st_uid == owner,
      opened.st_mode & 0o777 == 0o600,
      opened.st_size > 0,
      opened.st_size <= 64 * 1_024
    else { throw PowerVPNTargetsConfigurationError.invalid }

    var bytes = Data(count: Int(opened.st_size))
    let count = bytes.count
    let readCount = bytes.withUnsafeMutableBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return -1 }
      var total = 0
      while total < count {
        let result = Darwin.read(descriptor, base + total, count - total)
        if result <= 0 { return result == 0 ? total : -1 }
        total += result
      }
      return total
    }
    guard readCount == count else { throw PowerVPNTargetsConfigurationError.invalid }
    return bytes
  }
}

private struct ConfigurationCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init(_ stringValue: String) {
    self.stringValue = stringValue
  }

  init?(stringValue: String) {
    self.init(stringValue)
  }

  init?(intValue: Int) {
    return nil
  }
}
