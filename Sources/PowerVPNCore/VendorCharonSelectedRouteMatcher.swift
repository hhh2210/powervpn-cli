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
  private let selectedTokens: Set<Data>
  package let selectedRouteCount: Int

  init(keyData: Data, routes: [(network: UInt32, prefix: UInt8)]) {
    let localKey = SymmetricKey(data: keyData)
    let localTokens = Set(routes.map { Self.token($0, key: localKey) })
    key = localKey
    selectedTokens = localTokens
    selectedRouteCount = localTokens.count
  }

  package func matches(_ destinations: [String]) -> Set<Data> {
    Set(destinations.compactMap(Self.parseDestination).map { Self.token($0, key: key) })
      .intersection(selectedTokens)
  }

  private static func token(
    _ route: (network: UInt32, prefix: UInt8),
    key: SymmetricKey
  ) -> Data {
    var bytes = withUnsafeBytes(of: route.network.bigEndian, Array.init)
    bytes.append(route.prefix)
    return Data(HMAC<SHA256>.authenticationCode(for: Data(bytes), using: key))
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
  /// Builds a value-free matcher only when this exact resource covers the
  /// caller's fixed numeric SSH target. Neither the target nor route values
  /// escape this borrow.
  package func makeSelectedRouteMatcher(
    requiredTargetIPv4: UInt32
  ) throws -> VendorCharonSelectedRouteMatcher {
    guard let tunnels = candidate.tunnels else {
      throw VendorCharonSelectedRouteMatcherError.incompleteSnapshot
    }
    var routes: [(network: UInt32, prefix: UInt8)] = []
    for tunnel in tunnels {
      guard tunnel.family?.value == 4 else {
        throw VendorCharonSelectedRouteMatcherError.unsupportedFamily
      }
      guard let candidates = tunnel.routes else {
        throw VendorCharonSelectedRouteMatcherError.incompleteSnapshot
      }
      for candidate in candidates {
        guard let networkMaterial = candidate.network?.value,
          let prefixValue = candidate.prefix?.value
        else { throw VendorCharonSelectedRouteMatcherError.incompleteSnapshot }
        let network = try Self.parseSelectedIPv4(networkMaterial)
        let prefix = try Self.parseSelectedPrefix(prefixValue)
        routes.append((Self.masked(network, prefix: prefix), prefix))
      }
    }
    guard
      routes.contains(where: {
        Self.masked(requiredTargetIPv4, prefix: $0.prefix) == $0.network
      })
    else {
      throw VendorCharonSelectedRouteMatcherError.requiredTargetNotCovered
    }
    return VendorCharonSelectedRouteMatcher(
      keyData: Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }),
      routes: routes
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
