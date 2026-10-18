import Darwin
import Foundation

/// Fixed locations shared by the root helper, install.sh and the CLI.
public enum NativeHelperPaths {
  public static let label = "com.hhh2210.powervpn-native"
  public static let home = "/Library/PrivilegedHelperTools/com.hhh2210.powervpn-native"
  public static let runtime = home + "/runtime"
  public static let helper = home + "/powervpn-native-helper"
  public static let configuration = home + "/strongswan.conf"
  public static let owner = home + "/owner-uid"
  public static let charon = runtime + "/libexec/ipsec/charon"
  public static let runDirectory = "/var/run/powervpn-native"
  public static let vici = runDirectory + "/charon.vici"
  public static let control = runDirectory + "/control.sock"
}

/// One JSON line per connection in each direction. The helper only accepts
/// these three operations; it never runs a caller-chosen command.
public struct NativeHelperRequest: Codable, Equatable, Sendable {
  public enum Operation: String, Codable, Sendable {
    case status
    case routeAdd = "route-add"
    case routeDelete = "route-delete"
  }

  public let op: Operation
  public let ike: String?
  public let host: String?

  public init(op: Operation, ike: String? = nil, host: String? = nil) {
    self.op = op
    self.ike = ike
    self.host = host
  }
}

public struct NativeHelperResponse: Codable, Equatable, Sendable {
  public let ok: Bool
  /// Stable failure token when `ok` is false.
  public let error: String?
  public let charonRunning: Bool?
  public let interface: String?
  public let routes: [String]?

  public init(
    ok: Bool, error: String? = nil, charonRunning: Bool? = nil,
    interface: String? = nil, routes: [String]? = nil
  ) {
    self.ok = ok
    self.error = error
    self.charonRunning = charonRunning
    self.interface = interface
    self.routes = routes
  }
}

public enum NativeHelperClientError: Error, Equatable, Sendable {
  case unavailable
  case protocolError
}

public enum NativeHelperClient {
  public static func send(
    _ request: NativeHelperRequest,
    socketPath: String = NativeHelperPaths.control,
    timeoutSeconds: Int = 10
  ) throws -> NativeHelperResponse {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw NativeHelperClientError.unavailable }
    defer { close(fd) }
    var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    guard var address = unixAddress(socketPath) else { throw NativeHelperClientError.unavailable }
    let connected = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard connected == 0 else { throw NativeHelperClientError.unavailable }
    var line = try JSONEncoder().encode(request)
    line.append(0x0A)
    guard writeAll(fd, line) else { throw NativeHelperClientError.protocolError }
    guard let reply = readLine(fd, limit: 16_384),
      let response = try? JSONDecoder().decode(NativeHelperResponse.self, from: reply)
    else { throw NativeHelperClientError.protocolError }
    return response
  }
}

package func unixAddress(_ path: String) -> sockaddr_un? {
  var address = sockaddr_un()
  address.sun_family = sa_family_t(AF_UNIX)
  let bytes = Array(path.utf8)
  guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
  withUnsafeMutableBytes(of: &address.sun_path) { buffer in
    buffer.copyBytes(from: bytes)
  }
  return address
}

package func writeAll(_ fd: Int32, _ data: Data) -> Bool {
  var offset = 0
  while offset < data.count {
    let written = data.withUnsafeBytes {
      Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset)
    }
    if written <= 0 { return false }
    offset += written
  }
  return true
}

/// Reads up to the first newline; nil on EOF, timeout or overflow.
package func readLine(_ fd: Int32, limit: Int) -> Data? {
  var result = Data()
  var byte: UInt8 = 0
  while result.count < limit {
    let count = Darwin.read(fd, &byte, 1)
    if count <= 0 { return nil }
    if byte == 0x0A { return result }
    result.append(byte)
  }
  return nil
}

/// Dotted-quad IPv4 only; rejects leading zeros and anything ambiguous.
public func parseStrictIPv4(_ text: String) -> UInt32? {
  let parts = text.split(separator: ".", omittingEmptySubsequences: false)
  guard parts.count == 4 else { return nil }
  var value: UInt32 = 0
  for part in parts {
    guard !part.isEmpty, part.count <= 3, part.count == 1 || part.first != "0",
      part.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
      let octet = UInt32(part), octet <= 255
    else { return nil }
    value = (value << 8) | octet
  }
  return value
}

/// A host the helper may route into the tunnel: ordinary unicast only.
public func nativeRoutableHost(_ address: UInt32) -> Bool {
  let first = address >> 24
  if first == 0 || first == 127 || first >= 224 { return false }
  if address >> 16 == 0xA9FE { return false }  // 169.254/16
  return true
}

/// Summary of one IKE SA from a VICI `list-sas` event.
public struct NativeIKESummary: Equatable, Sendable {
  public let name: String
  public let state: String?
  public let remoteHost: String?
  public let localVirtualIPs: [String]
  public let childStates: [String]

  public var hasInstalledChild: Bool { childStates.contains("INSTALLED") }

  public static func parse(_ events: [VICIMessage]) -> [NativeIKESummary] {
    events.flatMap { event in
      event.elements.compactMap { element -> NativeIKESummary? in
        guard case .section(let name, let fields) = element else { return nil }
        var state: String?
        var remoteHost: String?
        var vips: [String] = []
        var children: [String] = []
        for field in fields {
          switch field {
          case .keyValue("state", let value): state = String(decoding: value, as: UTF8.self)
          case .keyValue("remote-host", let value):
            remoteHost = String(decoding: value, as: UTF8.self)
          case .list("local-vips", let values):
            vips = values.map { String(decoding: $0, as: UTF8.self) }
          case .section("child-sas", let sas):
            for child in sas {
              guard case .section(_, let childFields) = child else { continue }
              for case .keyValue("state", let value) in childFields {
                children.append(String(decoding: value, as: UTF8.self))
              }
            }
          default: continue
          }
        }
        return NativeIKESummary(
          name: name, state: state, remoteHost: remoteHost,
          localVirtualIPs: vips, childStates: children)
      }
    }
  }
}
