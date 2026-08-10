import Foundation

enum NetworkRouteFamily: String, Sendable {
  case inet
  case inet6

  var banner: String { self == .inet ? "Internet:" : "Internet6:" }
}

struct NetworkCanonicalRoute: Equatable, Sendable {
  let family: NetworkRouteFamily
  let destination: String
  let gateway: String
  let flags: String
  let interface: String
  let hasExpiration: Bool

  var record: String {
    "\(family.rawValue)\t\(destination)\t\(gateway)\t\(flags)\t\(interface)"
  }

  var persistent: Bool { !hasExpiration && !flags.contains("W") }
}

enum NetworkRouteCanonicalizer {
  private static let flagOrder = Array("UGHRDMmdCXLS12Wc3BbIiYrg")

  static func canonicalize(
    _ data: Data,
    family: NetworkRouteFamily,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil,
    effectiveSelectedRoute: NetworkCleanupEffectiveRouteSnapshot? = nil
  ) throws -> NetworkCleanupRouteSnapshot {
    let routes = try parse(data, family: family)
    let structuralRecords = routes.map(\.record).sorted()
    let persistentRecords = routes.filter(\.persistent).map(\.record).sorted()
    guard !persistentRecords.isEmpty else {
      throw NetworkCleanupCanonicalizationError.emptyInventory
    }
    let selectedTokens =
      family == .inet
      ? selectedRoutes?.matches(routes) ?? [] : []
    return NetworkCleanupRouteSnapshot(
      structural: .observed(
        count: structuralRecords.count,
        sha256: NetworkCleanupDigest.sha256(
          domain: "routes-\(family.rawValue)-structural",
          records: structuralRecords
        )
      ),
      persistent: .observed(
        count: persistentRecords.count,
        sha256: NetworkCleanupDigest.sha256(
          domain: "routes-\(family.rawValue)-persistent",
          records: persistentRecords
        )
      ),
      selectedRouteMatchCount: selectedTokens.count,
      selectedRouteTokens: selectedTokens,
      effectiveSelectedRoute: effectiveSelectedRoute
    )
  }

  static func parse(
    _ data: Data,
    family: NetworkRouteFamily
  ) throws -> [NetworkCanonicalRoute] {
    let lines = try NetworkCleanupText.lines(data)
    var phase = 0
    var routes: [NetworkCanonicalRoute] = []
    for rawLine in lines {
      let line = NetworkCleanupText.normalizedWhitespace(rawLine)
      if line.isEmpty { continue }
      switch phase {
      case 0:
        guard line == "Routing tables" else {
          throw NetworkCleanupCanonicalizationError.invalidShape
        }
        phase = 1
      case 1:
        guard line == family.banner else {
          throw NetworkCleanupCanonicalizationError.invalidShape
        }
        phase = 2
      case 2:
        guard line == "Destination Gateway Flags Netif Expire" else {
          throw NetworkCleanupCanonicalizationError.invalidShape
        }
        phase = 3
      default:
        let fields = line.split(separator: " ").map(String.init)
        guard fields.count == 4 || fields.count == 5,
          visible(fields[0]), visible(fields[1]), validFlags(fields[2]),
          validInterface(fields[3]),
          fields.count == 4 || fields[4] == "!" || positiveInteger(fields[4])
        else { throw NetworkCleanupCanonicalizationError.invalidShape }
        routes.append(
          NetworkCanonicalRoute(
            family: family,
            destination: fields[0],
            gateway: fields[1],
            flags: fields[2],
            interface: fields[3],
            hasExpiration: fields.count == 5
          ))
      }
    }
    guard phase == 3, !routes.isEmpty else {
      throw NetworkCleanupCanonicalizationError.emptyInventory
    }
    return routes
  }

  static func visible(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.allSatisfy { (0x21...0x7e).contains($0) }
  }

  static func validInterface(_ value: String) -> Bool {
    guard let first = value.utf8.first, (65...90).contains(first) || (97...122).contains(first)
    else { return false }
    return value.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        || $0 == 0x2e || $0 == 0x3a || $0 == 0x5f || $0 == 0x2d
    }
  }

  private static func validFlags(_ value: String) -> Bool {
    var previous = -1
    for character in value {
      guard let index = flagOrder.firstIndex(of: character), index > previous else {
        return false
      }
      previous = index
    }
    return !value.isEmpty
  }

  private static func positiveInteger(_ value: String) -> Bool {
    guard value.utf8.first != 0x30, let parsed = Int(value) else { return false }
    return parsed > 0
  }
}
