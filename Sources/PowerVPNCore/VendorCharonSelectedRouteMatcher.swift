import CryptoKit
import Foundation

package enum VendorCharonSelectedRouteMatcherError: Error, Equatable, Sendable {
  case incompleteSnapshot
  case unsupportedFamily
  case invalidNetwork
  case invalidPrefix
  case materialUnavailable
  case requiredTargetNotCovered
}

package final class VendorCharonSelectedRouteMatcher: @unchecked Sendable {
  private let key: SymmetricKey
  private let selectedDestinationTokens: Set<Data>
  private let selectedPrefixes: Set<UInt8>
  fileprivate let lineage: VendorCharonStartLineage
  package let requiredTargetIPv4: UInt32
  package let selectedRouteCount: Int

  package let selectedTunnelEncodedIndex: Int
  init(
    keyData: Data,
    routes: [(network: UInt32, prefix: UInt8)],
    requiredTargetIPv4: UInt32,
    selectedTunnelEncodedIndex: Int,
    lineage: VendorCharonStartLineage
  ) {
    let localKey = SymmetricKey(data: keyData)
    let localTokens = Set(routes.map { Self.destinationToken($0, key: localKey) })
    key = localKey
    selectedDestinationTokens = localTokens
    selectedPrefixes = Set(routes.map(\.prefix))
    self.requiredTargetIPv4 = requiredTargetIPv4
    self.lineage = lineage
    self.selectedTunnelEncodedIndex = selectedTunnelEncodedIndex
    selectedRouteCount = localTokens.count
  }

  var effectiveRouteCommand: NetworkCleanupCommand {
    .effectiveRoute(targetIPv4: requiredTargetIPv4)
  }

  func matches(_ routes: [NetworkCanonicalRoute]) -> Set<Data> {
    Set(
      routes.compactMap { route in
        guard let destination = Self.parseDestination(route.destination),
          selectedDestinationTokens.contains(Self.destinationToken(destination, key: key))
        else { return nil }
        return Self.bindingToken(
          destination: destination,
          family: route.family,
          gateway: route.gateway,
          interface: route.interface,
          key: key
        )
      })
  }

  /// Answers route coverage without exposing the selected route policy.
  package func permitsIPv4(_ address: UInt32) -> Bool {
    selectedPrefixes.contains { prefix in
      let destination = (Self.masked(address, prefix: prefix), prefix)
      return selectedDestinationTokens.contains(Self.destinationToken(destination, key: key))
    }
  }

  func effectiveRouteToken(
    routes: [NetworkCanonicalRoute],
    network: UInt32,
    prefix: UInt8,
    gateway: String?,
    interface: String
  ) throws -> Data? {
    let destination = (Self.masked(network, prefix: prefix), prefix)
    guard selectedDestinationTokens.contains(Self.destinationToken(destination, key: key)) else {
      return nil
    }
    let candidates = routes.filter { route in
      guard route.family == .inet,
        let parsed = Self.parseDestination(route.destination),
        parsed.network == destination.0,
        parsed.prefix == destination.1,
        route.interface == interface
      else { return false }
      return gateway.map { route.gateway == $0 } ?? true
    }
    guard candidates.count == 1, let route = candidates.first else {
      throw NetworkCleanupCanonicalizationError.invalidShape
    }
    return Self.bindingToken(
      destination: destination,
      family: route.family,
      gateway: route.gateway,
      interface: route.interface,
      key: key
    )
  }

  private static func destinationToken(
    _ route: (network: UInt32, prefix: UInt8),
    key: SymmetricKey
  ) -> Data {
    var bytes = Array("powervpn.selected-destination.v1\0".utf8)
    bytes.append(contentsOf: withUnsafeBytes(of: route.network.bigEndian, Array.init))
    bytes.append(route.prefix)
    return Data(HMAC<SHA256>.authenticationCode(for: Data(bytes), using: key))
  }

  private static func bindingToken(
    destination: (network: UInt32, prefix: UInt8),
    family: NetworkRouteFamily,
    gateway: String,
    interface: String,
    key: SymmetricKey
  ) -> Data {
    var bytes = Array("powervpn.selected-route-binding.v1\0\(family.rawValue)\0".utf8)
    bytes.append(contentsOf: withUnsafeBytes(of: destination.network.bigEndian, Array.init))
    bytes.append(destination.prefix)
    bytes.append(0)
    bytes.append(contentsOf: gateway.utf8)
    bytes.append(0)
    bytes.append(contentsOf: interface.utf8)
    return Data(
      HMAC<SHA256>.authenticationCode(
        for: Data(bytes),
        using: key
      ))
  }

  private static func parseDestination(_ text: String) -> (network: UInt32, prefix: UInt8)? {
    if text == "default" { return (0, 0) }
    let components = text.split(separator: "/", omittingEmptySubsequences: false)
    guard components.count <= 2,
      let address = parseAbbreviatedIPv4(components[0])
    else { return nil }
    let prefix: UInt8
    if components.count == 2 {
      guard let parsed = UInt8(components[1]), parsed <= 32 else { return nil }
      prefix = parsed
    } else {
      prefix = 32
    }
    return (masked(address, prefix: prefix), prefix)
  }

  private static func parseAbbreviatedIPv4(_ text: Substring) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...4).contains(parts.count) else { return nil }
    var address: UInt32 = 0
    for part in parts {
      guard !part.isEmpty, part.count <= 3,
        !(part.count > 1 && part.first == "0"),
        let value = UInt8(part)
      else { return nil }
      address = (address << 8) | UInt32(value)
    }
    return address << UInt32((4 - parts.count) * 8)
  }

  private static func masked(_ address: UInt32, prefix: UInt8) -> UInt32 {
    guard prefix > 0 else { return 0 }
    let mask = UInt32.max << UInt32(32 - prefix)
    return address & mask
  }
}

extension VendorCharonStartSnapshot {
  package func isBound(
    to matcher: VendorCharonSelectedRouteMatcher,
    requiredTargetIPv4: UInt32
  ) -> Bool {
    guard matcher.requiredTargetIPv4 == requiredTargetIPv4,
      matcher.selectedTunnelEncodedIndex == selectedTunnelEncodedIndex,
      let lineage = candidate.lineage
    else { return false }
    return matcher.lineage === lineage
  }

  /// Builds a value-free matcher only when this exact resource covers the
  /// caller's fixed numeric SSH target. Neither the target nor route values
  /// escape this borrow.
  package func makeSelectedRouteMatcher(
    requiredTargetIPv4: UInt32
  ) throws -> VendorCharonSelectedRouteMatcher {
    guard let tunnels = candidate.tunnels,
      let selectedTunnelEncodedIndex,
      tunnels.indices.contains(selectedTunnelEncodedIndex)
    else {
      throw VendorCharonSelectedRouteMatcherError.incompleteSnapshot
    }
    let tunnel = tunnels[selectedTunnelEncodedIndex]
    guard tunnel.family?.value == 4 else {
      throw VendorCharonSelectedRouteMatcherError.unsupportedFamily
    }
    guard let candidates = tunnel.routes else {
      throw VendorCharonSelectedRouteMatcherError.incompleteSnapshot
    }
    var routes: [(network: UInt32, prefix: UInt8)] = []
    for candidate in candidates {
      guard let networkMaterial = candidate.network?.value,
        let prefixValue = candidate.prefix?.value
      else { throw VendorCharonSelectedRouteMatcherError.incompleteSnapshot }
      let network = try Self.parseSelectedIPv4(networkMaterial)
      let prefix = try Self.parseSelectedPrefix(prefixValue)
      routes.append((Self.masked(network, prefix: prefix), prefix))
    }
    guard
      routes.contains(where: {
        Self.masked(requiredTargetIPv4, prefix: $0.prefix) == $0.network
      }),
      let lineage = candidate.lineage
    else {
      throw VendorCharonSelectedRouteMatcherError.requiredTargetNotCovered
    }
    return VendorCharonSelectedRouteMatcher(
      keyData: Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }),
      routes: routes,
      requiredTargetIPv4: requiredTargetIPv4,
      selectedTunnelEncodedIndex: selectedTunnelEncodedIndex,
      lineage: lineage
    )
  }

  private static func parseSelectedIPv4(
    _ material: any VendorCharonStartTextMaterial
  ) throws -> UInt32 {
    do {
      return try material.withUnsafeUTF8Bytes { bytes in
        let parts = bytes.split(separator: 0x2e, omittingEmptySubsequences: false)
        guard parts.count == 4 else {
          throw VendorCharonSelectedRouteMatcherError.invalidNetwork
        }
        var address: UInt32 = 0
        for part in parts {
          guard !part.isEmpty, part.count <= 3,
            !(part.count > 1 && part.first == 0x30),
            let value = decimal(part), value <= 255
          else { throw VendorCharonSelectedRouteMatcherError.invalidNetwork }
          address = (address << 8) | UInt32(value)
        }
        return address
      }
    } catch let error as VendorCharonSelectedRouteMatcherError {
      throw error
    } catch {
      throw VendorCharonSelectedRouteMatcherError.materialUnavailable
    }
  }

  private static func parseSelectedPrefix(_ value: VendorCharonRoutePrefix) throws -> UInt8 {
    switch value {
    case .integer(let prefix):
      guard (0...32).contains(prefix) else {
        throw VendorCharonSelectedRouteMatcherError.invalidPrefix
      }
      return UInt8(prefix)
    case .decimalText(let material):
      do {
        return try material.withUnsafeUTF8Bytes { bytes in
          guard let prefix = decimal(bytes), prefix <= 32 else {
            throw VendorCharonSelectedRouteMatcherError.invalidPrefix
          }
          return UInt8(prefix)
        }
      } catch let error as VendorCharonSelectedRouteMatcherError {
        throw error
      } catch {
        throw VendorCharonSelectedRouteMatcherError.materialUnavailable
      }
    }
  }

  private static func decimal<C: Collection>(_ bytes: C) -> Int?
  where C.Element == UInt8 {
    guard !bytes.isEmpty else { return nil }
    var value = 0
    for byte in bytes {
      guard (0x30...0x39).contains(byte) else { return nil }
      let (scaled, overflow1) = value.multipliedReportingOverflow(by: 10)
      let (next, overflow2) = scaled.addingReportingOverflow(Int(byte - 0x30))
      guard !overflow1, !overflow2 else { return nil }
      value = next
    }
    return value
  }

  private static func masked(_ address: UInt32, prefix: UInt8) -> UInt32 {
    guard prefix > 0 else { return 0 }
    return address & (UInt32.max << UInt32(32 - prefix))
  }
}

extension UnsafeRawBufferPointer {
  fileprivate func split(
    separator: UInt8,
    omittingEmptySubsequences: Bool
  ) -> [ArraySlice<UInt8>] {
    Array(self).split(
      separator: separator,
      omittingEmptySubsequences: omittingEmptySubsequences
    )
  }
}
