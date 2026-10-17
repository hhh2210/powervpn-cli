import Darwin
import Foundation
@preconcurrency import XPC

/// Temporary, scoped bridge for the native-daemon interoperability experiment.
/// Payloads never leave this process except over the selected Unix socket.
package enum NativeTrialMaterial {
  package enum Failure: Error {
    case incomplete, unsupported, targetOutsideResource, gatewayMatchesTarget
  }

  package static func withVendorStartMessage(
    snapshot: VendorCharonStartSnapshot, target: String,
    _ body: (xpc_object_t) throws -> Void
  ) throws {
    // Apply the same target/resource/gateway validation before encoding any
    // request, then limit the isolated vendor instance to that one resource.
    try withRequests(snapshot: snapshot, target: target, connectionName: "qm-vendor-scope") {
      _, _ in
    }
    guard let index = snapshot.selectedTunnelEncodedIndex else { throw Failure.incomplete }
    guard let vip = snapshot.candidate.common?.vip, let address = ipv4(try text(vip)) else {
      throw Failure.incomplete
    }
    var interfaces: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&interfaces) == 0 else { throw Failure.unsupported }
    defer { freeifaddrs(interfaces) }
    var entry = interfaces
    while let current = entry {
      if let socket = current.pointee.ifa_addr, socket.pointee.sa_family == UInt8(AF_INET) {
        let existing = UnsafeRawPointer(socket).assumingMemoryBound(to: sockaddr_in.self).pointee
          .sin_addr.s_addr
        guard existing != address.bigEndian else { throw Failure.unsupported }
      }
      entry = current.pointee.ifa_next
    }
    try snapshot.withEncodedStartMessage { message in
      guard let all = xpc_dictionary_get_value(message, "tunnels"),
        index >= 0, index < xpc_array_get_count(all)
      else { throw Failure.incomplete }
      let selected = xpc_array_get_value(all, index)
      let onlySelected = xpc_array_create(nil, 0)
      xpc_array_append_value(onlySelected, selected)
      xpc_dictionary_set_value(message, "tunnels", onlySelected)
      try body(message)
    }
  }

  package static func withRequests(
    snapshot: VendorCharonStartSnapshot,
    target: String,
    connectionName: String,
    includePrivateRule: Bool = false,
    proposalNumber: UInt8 = 0,
    observeGateway: ((String) throws -> Void)? = nil,
    _ body: (VICIMessage, VICIMessage) throws -> Void
  ) throws {
    guard proposalNumber <= 1 else { throw Failure.unsupported }
    guard let common = snapshot.candidate.common,
      let index = snapshot.selectedTunnelEncodedIndex,
      let tunnels = snapshot.candidate.tunnels, tunnels.indices.contains(index),
      let gateway = common.gateway, let sessionID = common.sessionID,
      let psk = common.psk, let ike = common.ike, let esp = common.esp,
      let port = common.ikePort, (1...65535).contains(port.value),
      let ikeLifetime = common.ikeLifetime, ikeLifetime.value > 0,
      let childLifetime = common.ipsecLifetime, childLifetime.value > 0
    else { throw Failure.incomplete }
    let selected = tunnels[index]
    // Portal/helper contract uses 4 for IPv4; the vendor converts that to
    // Darwin AF_INET (2) only inside its start_connection implementation.
    guard selected.family?.value == 4, let routes = selected.routes else {
      throw Failure.unsupported
    }
    guard let targetIP = ipv4(target),
      try routes.contains(where: { route in
        guard let network = route.network, let prefix = route.prefix else { return false }
        let prefixNumber: Int
        switch prefix.value {
        case .integer(let value): prefixNumber = Int(value)
        case .decimalText(let value):
          prefixNumber = try value.withUnsafeUTF8Bytes {
            Int(String(decoding: $0, as: UTF8.self)) ?? -1
          }
        }
        guard (0...32).contains(prefixNumber),
          let networkIP = ipv4(try text(network))
        else { return false }
        let mask: UInt32 = prefixNumber == 0 ? 0 : UInt32.max << (32 - prefixNumber)
        return targetIP & mask == networkIP & mask
      })
    else { throw Failure.targetOutsideResource }
    let gatewayText = try text(gateway)
    guard let gatewayIP = ipv4(gatewayText) else { throw Failure.unsupported }
    guard gatewayIP != targetIP else { throw Failure.gatewayMatchesTarget }
    try observeGateway?(gatewayText)

    // Explicit prefix prevents a numeric session identifier being inferred as
    // FQDN/IP. Hex is an in-memory identity encoding, never a stored credential.
    var id = Data("keyid:#".utf8)
    try sessionID.value.withUnsafeUTF8Bytes { bytes in
      let hex = Array("0123456789abcdef".utf8)
      for byte in bytes {
        id.append(hex[Int(byte >> 4)])
        id.append(hex[Int(byte & 15)])
      }
    }
    var secret = try bytes(psk)
    defer {
      id.resetBytes(in: 0..<id.count)
      secret.resetBytes(in: 0..<secret.count)
    }
    let shared = VICIMessage(elements: [
      .keyValue("id", connectionName), .keyValue("type", "IKE"),
      .keyValue(name: "data", value: secret),
      .list(name: "owners", values: [id]),
    ])
    let localTS: String
    if let vip = common.vip, !(try text(vip)).isEmpty {
      localTS = try text(vip) + "/32"
    } else {
      localTS = "dynamic"
    }
    if let vip = common.vip, ipv4(try text(vip)) != nil {
      let metadata: [String: Any] = [
        "stage": "portal_vip", "vip": try text(vip),
        "proposalNumber": proposalNumber, "epoch": Date().timeIntervalSince1970,
      ]
      FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: metadata))
      FileHandle.standardOutput.write(Data([10]))
    }
    // NC connection type 2 is finalized by vendor _set_adapter_name
    // (0x100122d69..0x100122d7b) with remote TS 0.0.0.0/0. The resource
    // CIDR remains in ADDRULE. Run only with native automatic routes disabled;
    // the existing runner installs the selected target /32 explicitly.
    let remoteTS = "0.0.0.0/0"
    FileHandle.standardError.write(
      Data("native NC remote_ts=\(remoteTS) addrule_scope=selected-resource\n".utf8))
    var childElements: [VICIElement] = [
      .list("local_ts", [localTS]), .list("remote_ts", [remoteTS]),
      .list("esp_proposals", try text(esp).split(separator: ",").map(String.init)),
      .keyValue("start_action", "none"), .keyValue("close_action", "none"),
      .keyValue("dpd_action", "none"), .keyValue("rekey_time", "0"),
      .keyValue("life_time", String(childLifetime.value)),
    ]
    if includePrivateRule {
      childElements.append(
        .keyValue(
          name: "leadsec_addrule", value: try privateRule(common: common, selected: selected)))
      childElements.append(.keyValue("leadsec_proposal_number", String(proposalNumber)))
    }
    let conn = VICIMessage(elements: [
      .section(
        name: connectionName,
        elements: [
          .keyValue("version", "1"), .keyValue("aggressive", "no"),
          .keyValue("local_port", "50020"),
          .keyValue("remote_port", String(port.value)),
          .keyValue("encap", "yes"), .keyValue("keyingtries", "1"),
          .keyValue("reauth_time", "0"), .keyValue("rekey_time", String(ikeLifetime.value)),
          .keyValue("rand_time", "0"), .keyValue("over_time", "0"),
          .list("remote_addrs", [gatewayText]),
          .list("proposals", try text(ike).split(separator: ",").map(String.init)),
          .section(
            name: "local", elements: [.keyValue("auth", "psk"), .keyValue(name: "id", value: id)]),
          .section(name: "remote", elements: [.keyValue("auth", "psk"), .keyValue("id", "%any")]),
          .section(
            name: "children",
            elements: [.section(name: "selected-resource", elements: childElements)]),
        ])
    ])
    try body(shared, conn)
  }

  /// The installed macOS start_connection pins ipsecctrl dialect to 0 at
  /// 0x1001aa7a0. It reads majorVersion later but never assigns it to that
  /// controller. Preserve the observed path, rather than infer dialect from
  /// the Portal version. rflag=0 supplies one address; rflag!=0 a named group.
  private static func privateRule(
    common: VendorCharonStartCommonCandidate,
    selected: VendorCharonStartTunnelCandidate
  ) throws -> Data {
    guard let vip = common.vip, let address = ipv4(try text(vip)),
      let flag = selected.resourceFlag, let routes = selected.routes
    else { throw Failure.incomplete }
    var body = Data()
    func append32(_ value: UInt32) {
      body.append(contentsOf: [
        UInt8(value >> 24), UInt8((value >> 16) & 255), UInt8((value >> 8) & 255),
        UInt8(value & 255),
      ])
    }
    append32(address)
    if flag.value == 0 {
      guard routes.count == 1, let network = routes[0].network,
        let prefix = routes[0].prefix, let net = ipv4(try text(network))
      else { throw Failure.unsupported }
      let bits: Int
      switch prefix.value {
      case .integer(let value): bits = Int(value)
      case .decimalText(let value):
        bits = try value.withUnsafeUTF8Bytes { Int(String(decoding: $0, as: UTF8.self)) ?? -1 }
      }
      guard (0...32).contains(bits) else { throw Failure.unsupported }
      append32(1)
      append32(net)
      append32(bits == 0 ? 0 : UInt32.max << (32 - bits))
      // Vendor dialect 0 category 1 has no secondary name or mapid.
      append32(0)
    } else {
      guard let name = selected.name else { throw Failure.incomplete }
      let nameBytes = try bytes(name)
      guard (1...64).contains(nameBytes.count) else { throw Failure.unsupported }
      append32(0)
      append32(1)
      body.append(UInt8(nameBytes.count))
      body.append(nameBytes)
    }
    let total = body.count + 4
    // VICI-only dialect byte; the next four bytes are the IKE payload header.
    var output = Data([0, 0, 0, UInt8(total >> 8), UInt8(total & 255)])
    output.append(body)
    return output
  }

  private static func bytes(_ value: VendorCharonStartTextValue) throws -> Data {
    try value.value.withUnsafeUTF8Bytes { Data($0) }
  }
  private static func text(_ value: VendorCharonStartTextValue) throws -> String {
    try value.value.withUnsafeUTF8Bytes { String(decoding: $0, as: UTF8.self) }
  }
  private static func ipv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var result: UInt32 = 0
    for part in parts {
      guard let value = UInt32(part), value <= 255 else { return nil }
      result = (result << 8) | value
    }
    return result
  }
}
