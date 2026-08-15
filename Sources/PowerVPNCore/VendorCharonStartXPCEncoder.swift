import Darwin
@preconcurrency import XPC

public enum VendorCharonStartEncodingError: Error, Equatable, Sendable {
  case incompleteSnapshot(VendorCharonStartField)
  case invalidTextMaterial(VendorCharonStartField)
  case textMaterialUnavailable(VendorCharonStartField)
  case allocationFailed
}

extension VendorCharonStartSnapshot {
  /// Builds one complete in-memory message and limits its intended lifetime to
  /// `body`. This method neither creates an XPC connection nor sends a message.
  package func withEncodedStartMessage(
    _ body: (xpc_object_t) throws -> Void
  ) throws {
    try VendorCharonStartXPCEncoder().withEncodedMessage(snapshot: self, body)
  }
}

enum VendorCharonStartXPCScope: String, Hashable, Sendable {
  case root
  case common
  case tunnel
  case route
}

struct VendorCharonStartXPCEncoder: Sendable {
  typealias EraseObserver = @Sendable (UnsafeRawBufferPointer) -> Void
  typealias InsertionObserver =
    @Sendable (VendorCharonStartXPCScope, VendorCharonStartField) -> Void

  private let eraseObserver: EraseObserver?
  private let insertionObserver: InsertionObserver?

  init(
    eraseObserver: EraseObserver? = nil,
    insertionObserver: InsertionObserver? = nil
  ) {
    self.eraseObserver = eraseObserver
    self.insertionObserver = insertionObserver
  }

  func withEncodedMessage(
    snapshot: VendorCharonStartSnapshot,
    _ body: (xpc_object_t) throws -> Void
  ) throws {
    let candidate = snapshot.candidate
    guard let commonCandidate = candidate.common else {
      throw VendorCharonStartEncodingError.incompleteSnapshot(.common)
    }
    guard let tunnelCandidates = candidate.tunnels, !tunnelCandidates.isEmpty else {
      throw VendorCharonStartEncodingError.incompleteSnapshot(.tunnels)
    }

    let root = xpc_dictionary_create(nil, nil, 0)
    setConstantString(root, key: "type", value: VendorCharonStartContract.requestType)
    record(.type, in: .root)
    setConstantString(root, key: "rpc", value: VendorCharonStartContract.requestRPC)
    record(.rpc, in: .root)
    let common = try makeCommon(commonCandidate)
    setValue(root, key: "common", value: common)
    record(.common, in: .root)
    let tunnels = try makeTunnels(tunnelCandidates)
    setValue(root, key: "tunnels", value: tunnels)
    record(.tunnels, in: .root)
    try body(root)
  }

  private func makeCommon(
    _ common: VendorCharonStartCommonCandidate
  ) throws -> xpc_object_t {
    let result = xpc_dictionary_create(nil, nil, 0)
    try setText(result, "sessionid", required(common.sessionID, .sessionID), .sessionID)
    record(.sessionID, in: .common)
    if let vip = common.vip {
      try setText(result, "vip", vip, .vip)
      record(.vip, in: .common)
    }
    if let vipv6 = common.vipv6 {
      try setText(result, "vipv6", vipv6, .vipv6)
    } else {
      // The official client always supplies this key. `setup_tundevice`
      // unconditionally calls `strlen` on its UTF8String
      // (`0x1001a9ebf`–`0x1001a9ec6`), so absence must project to `""`.
      setConstantString(result, key: "vipv6", value: "")
    }
    record(.vipv6, in: .common)
    try setText(result, "gateway", required(common.gateway, .gateway), .gateway)
    record(.gateway, in: .common)
    setInteger(result, "ike_port", try required(common.ikePort, .ikePort).value)
    record(.ikePort, in: .common)
    setInteger(
      result,
      "majorVersion",
      try required(common.majorVersion, .majorVersion).value
    )
    record(.majorVersion, in: .common)
    try setText(result, "ike", required(common.ike, .ike), .ike)
    record(.ike, in: .common)
    try setText(result, "esp", required(common.esp, .esp), .esp)
    record(.esp, in: .common)
    try setText(result, "psk", required(common.psk, .psk), .psk)
    record(.psk, in: .common)
    setInteger(
      result,
      "ike_life_time",
      try required(common.ikeLifetime, .ikeLifetime).value
    )
    record(.ikeLifetime, in: .common)
    setInteger(
      result,
      "ipsec_life_time",
      try required(common.ipsecLifetime, .ipsecLifetime).value
    )
    record(.ipsecLifetime, in: .common)
    return result
  }

  private func makeTunnels(
    _ tunnels: [VendorCharonStartTunnelCandidate]
  ) throws -> xpc_object_t {
    let result = xpc_array_create(nil, 0)
    for tunnel in tunnels {
      xpc_array_append_value(result, try makeTunnel(tunnel))
    }
    return result
  }

  private func makeTunnel(
    _ tunnel: VendorCharonStartTunnelCandidate
  ) throws -> xpc_object_t {
    let result = xpc_dictionary_create(nil, nil, 0)
    setInteger(result, "authority", try required(tunnel.authority, .authority).value)
    record(.authority, in: .tunnel)
    setInteger(result, "status", try required(tunnel.status, .status).value)
    record(.status, in: .tunnel)
    try setText(
      result,
      "tunnel-name",
      required(tunnel.tunnelName, .tunnelName),
      .tunnelName
    )
    record(.tunnelName, in: .tunnel)
    setInteger(result, "family", try required(tunnel.family, .family).value)
    record(.family, in: .tunnel)
    setInteger(result, "rflag", try required(tunnel.resourceFlag, .resourceFlag).value)
    record(.resourceFlag, in: .tunnel)
    try setText(result, "name", required(tunnel.name, .name), .name)
    record(.name, in: .tunnel)
    let routes = try makeRoutes(required(tunnel.routes, .routes))
    setValue(result, key: "routes", value: routes)
    record(.routes, in: .tunnel)
    try setText(result, "mapid", required(tunnel.mapID, .mapID), .mapID)
    record(.mapID, in: .tunnel)
    if let mode = tunnel.negotiateMode {
      setInteger(result, "negotiate-mode", mode.value)
      record(.negotiateMode, in: .tunnel)
    }
    return result
  }

  private func makeRoutes(
    _ routes: [VendorCharonStartRouteCandidate]
  ) throws -> xpc_object_t {
    let result = xpc_array_create(nil, 0)
    for route in routes {
      let encoded = xpc_dictionary_create(nil, nil, 0)
      try setText(encoded, "net", required(route.network, .routeNetwork), .routeNetwork)
      record(.routeNetwork, in: .route)
      let prefix = try required(route.prefix, .routePrefix)
      switch prefix.value {
      case .integer(let value):
        setInteger(encoded, "prfix", value)
      case .decimalText(let material):
        try setTextMaterial(
          encoded,
          "prfix",
          material,
          .routePrefix,
          contentValidator: validDecimalPrefix
        )
      }
      record(.routePrefix, in: .route)
      xpc_array_append_value(result, encoded)
    }
    return result
  }

  private func setText(
    _ dictionary: xpc_object_t,
    _ key: String,
    _ value: VendorCharonStartTextValue,
    _ field: VendorCharonStartField
  ) throws {
    try setTextMaterial(dictionary, key, value.value, field)
  }

  private func setTextMaterial(
    _ dictionary: xpc_object_t,
    _ key: String,
    _ material: any VendorCharonStartTextMaterial,
    _ field: VendorCharonStartField,
    contentValidator: (UnsafeRawBufferPointer) -> Bool = { _ in true }
  ) throws {
    let allowsEmpty =
      VendorCharonStartContract.orderedRules.first {
        $0.field == field
      }?.allowsEmptyText == true
    let minimum = allowsEmpty ? 0 : 1
    let declaredByteCount = material.byteCount
    guard
      (minimum...VendorCharonStartValidator.maximumTextBytes).contains(declaredByteCount)
    else {
      throw VendorCharonStartEncodingError.invalidTextMaterial(field)
    }
    do {
      try material.withUnsafeUTF8Bytes { bytes in
        guard bytes.count == declaredByteCount, !bytes.contains(0), contentValidator(bytes) else {
          throw VendorCharonStartEncodingError.invalidTextMaterial(field)
        }
        let (bufferCount, overflow) = bytes.count.addingReportingOverflow(1)
        guard !overflow, let buffer = malloc(bufferCount) else {
          throw VendorCharonStartEncodingError.allocationFailed
        }
        defer {
          _ = memset_s(buffer, bufferCount, 0, bufferCount)
          eraseObserver?(UnsafeRawBufferPointer(start: buffer, count: bufferCount))
          free(buffer)
        }
        if !bytes.isEmpty {
          _ = memcpy(buffer, bytes.baseAddress!, bytes.count)
        }
        buffer.storeBytes(of: UInt8(0), toByteOffset: bytes.count, as: UInt8.self)
        key.withCString { keyPointer in
          xpc_dictionary_set_string(
            dictionary,
            keyPointer,
            buffer.assumingMemoryBound(to: CChar.self)
          )
        }
      }
    } catch let error as VendorCharonStartEncodingError {
      throw error
    } catch {
      throw VendorCharonStartEncodingError.textMaterialUnavailable(field)
    }
  }

  private func validDecimalPrefix(_ bytes: UnsafeRawBufferPointer) -> Bool {
    var value: Int32 = 0
    for byte in bytes {
      guard (0x30...0x39).contains(byte) else { return false }
      let (scaled, overflow1) = value.multipliedReportingOverflow(by: 10)
      let (next, overflow2) = scaled.addingReportingOverflow(Int32(byte - 0x30))
      guard !overflow1, !overflow2 else { return false }
      value = next
    }
    return (0...128).contains(value)
  }

  private func setConstantString(
    _ dictionary: xpc_object_t,
    key: String,
    value: String
  ) {
    key.withCString { keyPointer in
      value.withCString { valuePointer in
        xpc_dictionary_set_string(dictionary, keyPointer, valuePointer)
      }
    }
  }

  private func setInteger(_ dictionary: xpc_object_t, _ key: String, _ value: Int32) {
    key.withCString { xpc_dictionary_set_int64(dictionary, $0, Int64(value)) }
  }

  private func setValue(_ dictionary: xpc_object_t, key: String, value: xpc_object_t) {
    key.withCString { xpc_dictionary_set_value(dictionary, $0, value) }
  }

  private func record(
    _ field: VendorCharonStartField,
    in scope: VendorCharonStartXPCScope
  ) {
    insertionObserver?(scope, field)
  }

  private func required<Value>(
    _ value: Value?,
    _ field: VendorCharonStartField
  ) throws -> Value {
    guard let value else { throw VendorCharonStartEncodingError.incompleteSnapshot(field) }
    return value
  }
}
