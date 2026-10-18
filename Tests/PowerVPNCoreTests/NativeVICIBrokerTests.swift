import Darwin
import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeVICIBrokerTests {
  private func request(_ command: String, _ fields: [VICIElement] = []) throws -> Data {
    try VICINamedRequest(command: command, message: .init(elements: fields)).encodedPayload()
  }

  @Test func permitsTheProductWireContractAndRejectsExtraConnectionFields() throws {
    try NativeTrialMaterial.withRequests(
      snapshot: NativeTrialMaterialTests().snapshot(gateway: "192.0.2.1"),
      target: "198.51.100.7", connectionName: "powervpn-test-1234", includePrivateRule: true
    ) { shared, connection in
      let sharedPayload = try request("load-shared", shared.elements)
      let connectionPayload = try request("load-conn", connection.elements)
      #expect(NativeVICIAllowlist.permits(sharedPayload))
      #expect(NativeVICIAllowlist.permits(connectionPayload))
      guard case .section(let name, let fields) = connection.elements[0] else {
        Issue.record("missing generated connection")
        return
      }
      for unwanted in ["updown", "file", "certs", "pools", "send_cert"] {
        let modified = fields + [.keyValue(unwanted, "synthetic")]
        #expect(
          !NativeVICIAllowlist.permits(
            try request("load-conn", [.section(name: name, elements: modified)])))
      }
      let nested = fields.map { element -> VICIElement in
        guard case .section("local", let auth) = element else { return element }
        return .section(
          name: "local", elements: auth + [.keyValue("file", "/synthetic-certificate")])
      }
      #expect(
        !NativeVICIAllowlist.permits(
          try request("load-conn", [.section(name: name, elements: nested)])))
    }
  }

  @Test func rejectsUnsupportedOperationsAndMalformedFrames() throws {
    for command in [
      "load-token", "load-key", "load-cert", "reload-settings", "clear-creds", "anything",
    ] {
      #expect(!NativeVICIAllowlist.permits(try request(command)))
    }
    #expect(!NativeVICIAllowlist.permits(Data([1])))
    #expect(!NativeVICIAllowlist.permits(Data([0, 20, 65])))
    #expect(!NativeVICIAllowlist.permits(try request("version", [.keyValue("x", "y")])))
    #expect(!NativeVICIAllowlist.permits(try request("list-sas", [.keyValue("noblock", "yes")])))
    #expect(!NativeVICIAllowlist.permits(try request("terminate", [.keyValue("ike", "unrelated")])))
    var registration = try VICIPacketCodec.encodeEventRegistration("list-sa", register: true)
    #expect(NativeVICIAllowlist.permits(registration))
    registration.append(0)
    #expect(!NativeVICIAllowlist.permits(registration))
  }

  @Test func checksEveryFrameAndForwardsDaemonReplies() throws {
    let client = try pair()
    let daemon = try pair()
    defer {
      close(client[0])
      close(daemon[0])
    }
    let finished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
      NativeVICIBroker.relay(client: client[1], upstream: daemon[1])
      close(client[1])
      close(daemon[1])
      finished.signal()
    }
    let version = try request("version")
    #expect(NativeVICIBroker.writeFrame(client[0], version))
    #expect(NativeVICIBroker.readFrame(daemon[0]) == version)
    let response = Data([VICIPacketOperation.commandResponse.rawValue])
    #expect(NativeVICIBroker.writeFrame(daemon[0], response))
    #expect(NativeVICIBroker.readFrame(client[0]) == response)
    #expect(NativeVICIBroker.writeFrame(client[0], try request("load-token")))
    #expect(finished.wait(timeout: .now() + 3) == .success)
    #expect(NativeVICIBroker.readFrame(daemon[0]) == nil)
  }

  @Test func rejectsOversizedLengthBeforeReadingBody() throws {
    let sockets = try pair()
    defer { for socket in sockets { close(socket) } }
    #expect(writeAll(sockets[0], Data([0, 9, 0, 0])))
    #expect(NativeVICIBroker.readFrame(sockets[1]) == nil)
  }

  private func pair() throws -> [Int32] {
    var sockets = [Int32](repeating: -1, count: 2)
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    for socket in sockets {
      var timeout = timeval(tv_sec: 3, tv_usec: 0)
      setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }
    return sockets
  }
}
