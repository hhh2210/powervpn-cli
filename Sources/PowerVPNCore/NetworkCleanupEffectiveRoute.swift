import Foundation

package struct NetworkCleanupEffectiveRouteSnapshot: Equatable, Sendable {
  let state: NetworkCleanupObservationState
  let selectedRouteToken: Data?

  static func observed(selectedRouteToken: Data?) -> Self {
    Self(state: .observed, selectedRouteToken: selectedRouteToken)
  }

  static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(state: state, selectedRouteToken: nil)
  }

  var isObserved: Bool { state == .observed }
}

enum NetworkCleanupEffectiveRouteCanonicalizer {
  private static let accepted = ["route to", "destination", "mask", "gateway", "interface"]
  private static let required = ["route to", "destination", "interface"]

  static func canonicalize(
    _ data: Data,
    matcher: VendorCharonSelectedRouteMatcher,
    routes: [NetworkCanonicalRoute]
  ) throws -> NetworkCleanupEffectiveRouteSnapshot {
    var values: [String: String] = [:]
    for rawLine in try NetworkCleanupText.lines(data) {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      guard !line.isEmpty, let colon = line.firstIndex(of: ":") else { continue }
      let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
      guard accepted.contains(key) else { continue }
      let value = NetworkCleanupText.normalizedWhitespace(
        String(line[line.index(after: colon)...])
      )
      guard !value.isEmpty else { throw NetworkCleanupCanonicalizationError.invalidShape }
      guard values.updateValue(value, forKey: key) == nil else {
        throw NetworkCleanupCanonicalizationError.duplicateValue
      }
    }
    guard required.allSatisfy({ values[$0] != nil }),
      values["route to"] == NetworkCleanupCommand.canonicalIPv4(matcher.requiredTargetIPv4),
      let destination = values["destination"],
      let interface = values["interface"],
      NetworkRouteCanonicalizer.validInterface(interface)
    else { throw NetworkCleanupCanonicalizationError.invalidShape }
    let gateway = values["gateway"]
    guard gateway.map(NetworkRouteCanonicalizer.visible) ?? true else {
      throw NetworkCleanupCanonicalizationError.invalidShape
    }

    let route = try routeDestination(
      destination,
      mask: values["mask"],
      target: NetworkCleanupCommand.canonicalIPv4(matcher.requiredTargetIPv4)
    )
    return .observed(
      selectedRouteToken: try matcher.effectiveRouteToken(
        routes: routes,
        network: route.network,
        prefix: route.prefix,
        gateway: gateway,
        interface: interface
      ))
  }

  private static func routeDestination(
    _ destination: String,
    mask: String?,
    target: String
  ) throws -> (network: UInt32, prefix: UInt8) {
    if destination == "default" {
      guard mask == "default" else {
        throw NetworkCleanupCanonicalizationError.invalidShape
      }
      return (0, 0)
    }
    guard let address = parseIPv4(destination) else {
      throw NetworkCleanupCanonicalizationError.invalidShape
    }
    guard let mask else {
      guard destination == target else {
        throw NetworkCleanupCanonicalizationError.invalidShape
      }
      return (address, 32)
    }
    guard mask != "default",
      let maskValue = parseIPv4(mask),
      let prefix = contiguousPrefix(maskValue),
      masked(address, prefix: prefix) == address
    else { throw NetworkCleanupCanonicalizationError.invalidShape }
    return (address, prefix)
  }

  private static func parseIPv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var value: UInt32 = 0
    for part in parts {
      guard !part.isEmpty, part.count <= 3,
        !(part.count > 1 && part.first == "0"),
        let octet = UInt8(part)
      else { return nil }
      value = (value << 8) | UInt32(octet)
    }
    return value
  }

  private static func contiguousPrefix(_ mask: UInt32) -> UInt8? {
    var sawZero = false
    var prefix: UInt8 = 0
    for shift in stride(from: 31, through: 0, by: -1) {
      if mask & (UInt32(1) << UInt32(shift)) == 0 {
        sawZero = true
      } else {
        guard !sawZero else { return nil }
        prefix += 1
      }
    }
    return prefix
  }

  private static func masked(_ address: UInt32, prefix: UInt8) -> UInt32 {
    guard prefix > 0 else { return 0 }
    return address & (UInt32.max << UInt32(32 - prefix))
  }
}
