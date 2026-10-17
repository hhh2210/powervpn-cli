import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeTrialMaterialTests {
  func snapshot(gateway: String = "127.0.0.1", resourceName: String = "") throws
    -> VendorCharonStartSnapshot
  {
    let values = CoreStartTestValues()
    let candidate = VendorCharonStartCandidate(
      lineage: values.lineage,
      common: VendorCharonStartCommonCandidate(
        sessionID: values.text("synthetic:ID-keyid"), vip: values.text("192.0.2.9"),
        gateway: values.text(gateway), ikePort: values.integer(500),
        majorVersion: values.integer(1), ike: values.text("aes128-sha256-modp2048"),
        esp: values.text("aes128-sha256"), psk: values.text("001122-no-hex-decoding"),
        ikeLifetime: values.integer(3600), ipsecLifetime: values.integer(3600)),
      tunnels: [
        VendorCharonStartTunnelCandidate(
          authority: values.integer(1), status: values.integer(1),
          tunnelName: values.text("selected"), family: values.integer(4),
          resourceFlag: values.integer(0),
          name: values.text(resourceName),
          routes: [
            VendorCharonStartRouteCandidate(
              network: values.text("198.51.100.0"), prefix: values.prefix(24))
          ],
          mapID: values.text("synthetic-map"))
      ])
    return try #require(VendorCharonStartValidator.validate(candidate).snapshot)
  }

  @Test func mapsRawPSKAndExplicitKeyIDAndSelectedScope() throws {
    try NativeTrialMaterial.withRequests(
      snapshot: snapshot(), target: "198.51.100.7", connectionName: "native-synthetic"
    ) { shared, conn in
      #expect(shared.value(forKey: "data") == Data("001122-no-hex-decoding".utf8))
      let connWire = try VICIMessageCodec.encode(conn)
      #expect(connWire.range(of: Data("keyid:#73796e7468657469633a49442d6b65796964".utf8)) != nil)
      #expect(connWire.range(of: Data("0.0.0.0/0".utf8)) != nil)
      #expect(connWire.range(of: Data("192.0.2.9/32".utf8)) != nil)
      #expect(connWire.range(of: Data("001122-no-hex-decoding".utf8)) == nil)
    }
  }

  @Test func routeRuleMatchesVendorDialectZeroWithoutNameOrMapID() throws {
    try NativeTrialMaterial.withRequests(
      snapshot: snapshot(resourceName: "synthetic-name"),
      target: "198.51.100.7", connectionName: "synthetic-rule", includePrivateRule: true
    ) { _, conn in
      func findRule(_ elements: [VICIElement]) -> Data? {
        for element in elements {
          switch element {
          case .keyValue(let name, let value) where name == "leadsec_addrule": return value
          case .section(_, let nested): if let value = findRule(nested) { return value }
          default: break
          }
        }
        return nil
      }
      // VICI dialect byte + 24-byte type-18 envelope: VIP, one net/mask,
      // zero named rules. Resource name and mapid are absent for rflag=0.
      #expect(
        findRule(conn.elements)
          == Data([
            0, 0, 0, 0, 24,
            192, 0, 2, 9, 0, 0, 0, 1, 198, 51, 100, 0,
            255, 255, 255, 0, 0, 0, 0, 0,
          ]))
    }
  }

  @Test func rejectsTargetOutsideSelectedResourceBeforeCallback() throws {
    var called = false
    #expect(throws: NativeTrialMaterial.Failure.self) {
      try NativeTrialMaterial.withRequests(
        snapshot: snapshot(), target: "203.0.113.7", connectionName: "native-synthetic"
      ) { _, _ in called = true }
    }
    #expect(!called)
  }

  @Test func targetCannotEqualIKEGatewayAndGatewayObservationIsScoped() throws {
    var invoked = false
    let markInvoked: (String) throws -> Void = { _ in invoked = true }
    #expect(throws: NativeTrialMaterial.Failure.gatewayMatchesTarget) {
      try NativeTrialMaterial.withRequests(
        snapshot: snapshot(gateway: "198.51.100.7"), target: "198.51.100.7",
        connectionName: "synthetic", observeGateway: markInvoked
      ) { _, _ in invoked = true }
    }
    #expect(!invoked)
    var observed: String?
    let recordObserved: (String) throws -> Void = { observed = $0 }
    try NativeTrialMaterial.withRequests(
      snapshot: snapshot(), target: "198.51.100.7", connectionName: "synthetic",
      observeGateway: recordObserved
    ) { _, _ in }
    #expect(observed == "127.0.0.1")
  }

  @Test(.enabled(if: ProcessInfo.processInfo.environment["NATIVE_TRIAL_SYNTHETIC_SOCKET"] != nil))
  func syntheticFakeKernelVICILoadRoundTrip() throws {
    let socket = try #require(ProcessInfo.processInfo.environment["NATIVE_TRIAL_SYNTHETIC_SOCKET"])
    let session = try VICISession(socketPath: socket)
    defer { session.close() }
    let name = "native-synthetic-roundtrip"
    _ = try session.version()
    try NativeTrialMaterial.withRequests(
      snapshot: snapshot(), target: "198.51.100.7", connectionName: name
    ) { shared, conn in
      _ = try session.request(command: "load-shared", message: shared)
      defer {
        _ = try? session.request(
          command: "unload-shared", message: VICIMessage(elements: [.keyValue("id", name)]))
      }
      _ = try session.request(command: "load-conn", message: conn)
      defer {
        _ = try? session.request(
          command: "unload-conn", message: VICIMessage(elements: [.keyValue("name", name)]))
      }
      let connections = try session.streamedRequest(command: "list-conns", event: "list-conn")
      #expect(connections.events.contains { $0.containsTopLevelSection(named: name) })
      // Deliberately no initiate call; this test sends no IKE packet.
    }
  }

  @Test(.enabled(if: ProcessInfo.processInfo.environment["NATIVE_TRIAL_PRIVATE_SOCKET"] != nil))
  func syntheticPrivatePayloadVICIValidation() throws {
    let socket = try #require(ProcessInfo.processInfo.environment["NATIVE_TRIAL_PRIVATE_SOCKET"])
    let session = try VICISession(socketPath: socket)
    defer { session.close() }
    let name = "native-private-synthetic"
    // Canonical CP4A invented fixture: one dialect-0 route and one opaque name.
    let payload = Data([
      0, 0, 0, 0, 29, 192, 0, 2, 10, 0, 0, 0, 1,
      198, 51, 100, 0, 255, 255, 255, 0, 0, 0, 0, 1, 4, 0xde, 0xad, 0xbe, 0xef,
    ])
    func inject(_ elements: [VICIElement], _ bytes: Data, name field: String = "leadsec_addrule")
      -> [VICIElement]
    {
      elements.map { element in
        if case .section(let key, let nested) = element {
          return .section(
            name: key,
            elements: key == "selected-resource"
              ? nested.filter {
                if case .keyValue(let name, _) = $0 { return name != field }
                return true
              } + [.keyValue(name: field, value: bytes)] : inject(nested, bytes, name: field))
        }
        return element
      }
    }
    try NativeTrialMaterial.withRequests(
      snapshot: snapshot(), target: "198.51.100.7", connectionName: name
    ) { _, connection in
      _ = try session.request(
        command: "load-conn", message: VICIMessage(elements: inject(connection.elements, payload)))
      _ = try session.request(
        command: "unload-conn", message: VICIMessage(elements: [.keyValue("name", name)]))
      var invalid = payload
      invalid[1] = 18  // a nonzero next-payload is rejected by the profile gate
      #expect(throws: VICISessionError.commandFailed("load-conn")) {
        _ = try session.request(
          command: "load-conn", message: VICIMessage(elements: inject(connection.elements, invalid))
        )
      }
    }
    try NativeTrialMaterial.withRequests(
      snapshot: snapshot(), target: "198.51.100.7", connectionName: name, includePrivateRule: true
    ) { _, connection in
      for value in ["0", "1"] {
        let candidate = VICIMessage(
          elements: inject(connection.elements, Data(value.utf8), name: "leadsec_proposal_number"))
        _ = try session.request(command: "load-conn", message: candidate)
        _ = try session.request(
          command: "unload-conn", message: VICIMessage(elements: [.keyValue("name", name)]))
      }
      for value in ["", "2", "01", "255", "-1"] {
        let candidate = VICIMessage(
          elements: inject(connection.elements, Data(value.utf8), name: "leadsec_proposal_number"))
        #expect(throws: VICISessionError.commandFailed("load-conn")) {
          _ = try session.request(command: "load-conn", message: candidate)
        }
      }
    }
  }
}
