import Foundation
import Testing
@preconcurrency import XPC

@testable import PowerVPNCore

@Suite struct VendorCharonControlWireCodecTests {
  @Test func stopCopiesOnlyGatewayFromExactEncodedStartEnvelope() throws {
    #expect(SystemVendorCharonControlConnectionDriver.serviceName == "com.leadsec.charon-xpc")
    #expect(
      VendorCharonStopContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "stop_connection"),
      ])

    let fixture = ControlSnapshotFixture()
    var startGateway: String?
    var retainedContext: VendorCharonStopContext?
    try fixture.snapshot().withEncodedStartMessage { start in
      let common = try dictionary(start, "common")
      startGateway = try string(common, "gateway")
      retainedContext = VendorCharonControlWireCodec.stopContext(
        copyingGatewayFromStartRequest: start
      )
    }
    fixture.gateway.failBorrows()

    let stop = VendorCharonControlWireCodec.makeStopRequest(
      context: try #require(retainedContext)
    )
    #expect(hasExactKeys(stop, ["type", "rpc", "common"]))
    #expect((try? string(stop, "type")) == "rpc")
    #expect((try? string(stop, "rpc")) == "stop_connection")
    let common = try dictionary(stop, "common")
    #expect(hasExactKeys(common, ["gateway"]))
    #expect(try string(common, "gateway") == startGateway)
  }
  @Test func dictionarySignatureSortsKeysAndDropsValues() {
    let secretValue = "utun-value-must-not-escape"
    let object = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_int64(object, "state", 5)
    xpc_dictionary_set_string(object, "name", secretValue)
    xpc_dictionary_set_bool(object, "get_tun_name_success", true)

    let signature = VendorCharonControlWireCodec.dictionarySignature(object)

    #expect(
      signature == [
        "get_tun_name_success:bool",
        "name:string",
        "state:int64",
      ])
    #expect(!retainedStrings(in: signature as Any).contains(secretValue))
    #expect(
      VendorCharonControlWireCodec.dictionarySignature(
        xpc_dictionary_create(nil, nil, 0)
      ) == [])
    #expect(
      VendorCharonControlWireCodec.dictionarySignature(xpc_array_create(nil, 0)) == nil)
  }

  @Test func exactStatusShapeDecodesRawIntegersWithoutRetainingName() throws {
    let empty = xpc_dictionary_create(nil, nil, 0)
    #expect(
      VendorCharonControlWireCodec.connectionEvent(empty) == .emptyDispatcherTail)

    let secretName = "value-must-not-escape"
    let event = VendorCharonControlWireCodec.connectionEvent(
      statusObject(name: secretName, type: 41, phase: 2, state: 5))
    let signal = try #require(statusSignal(event))

    #expect(signal == VendorCharonStatusSignal(type: 41, phase: 2, state: 5))
    #expect(signal.classification == .connected)
    #expect(retainedStrings(in: event).isEmpty)
    #expect(!String(reflecting: event).contains(secretName))
  }

  @Test func statusClassificationIsFailClosed() throws {
    let cases: [(Int64, Int64, VendorCharonStatusClassification)] = [
      (2, 5, .connected),
      (2, 7, .disconnected),
      (2, 9, .unclassified),
      (2, 10, .unclassified),
      (2, 777, .unclassified),
      (1, 5, .unclassified),
    ]

    for (phase, state, expected) in cases {
      let event = VendorCharonControlWireCodec.connectionEvent(
        statusObject(name: "synthetic", type: -19, phase: phase, state: state))
      let signal = try #require(statusSignal(event))
      #expect(signal.type == -19)
      #expect(signal.phase == phase)
      #expect(signal.state == state)
      #expect(signal.classification == expected)
    }
  }

  @Test func exactTunnelNameReportShapesDecodeValueFreeSuccess() {
    let names: [(namev4: String?, namev6: String?)] = [
      (nil, nil),
      ("utun-v4-must-not-escape", nil),
      (nil, "utun-v6-must-not-escape"),
      ("utun-v4-must-not-escape", "utun-v6-must-not-escape"),
    ]

    for success in [false, true] {
      for names in names {
        let event = VendorCharonControlWireCodec.connectionEvent(
          tunnelNameObject(
            success: success,
            namev4: names.namev4,
            namev6: names.namev6
          ))

        #expect(event == .tunnelNameReported(success: success))
        #expect(retainedStrings(in: event).isEmpty)
        #expect(!String(reflecting: event).contains("utun-v4-must-not-escape"))
        #expect(!String(reflecting: event).contains("utun-v6-must-not-escape"))
      }
    }
  }

  @Test func malformedTunnelNameReportDictionariesAreRejected() {
    let extra = tunnelNameObject(success: true, namev4: nil, namev6: nil)
    xpc_dictionary_set_bool(extra, "extra", true)
    #expect(VendorCharonControlWireCodec.connectionEvent(extra) == .unexpectedDictionary)

    let missingSuccess = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(missingSuccess, "namev4", "utun4")
    #expect(
      VendorCharonControlWireCodec.connectionEvent(missingSuccess)
        == .unexpectedDictionary)

    let wrongSuccess = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(wrongSuccess, "get_tun_name_success", "true")
    #expect(
      VendorCharonControlWireCodec.connectionEvent(wrongSuccess)
        == .unexpectedDictionary)
    let staleSuccessKey = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_bool(staleSuccessKey, "success", true)
    #expect(
      VendorCharonControlWireCodec.connectionEvent(staleSuccessKey)
        == .unexpectedDictionary)

    let wrongNamev4 = tunnelNameObject(success: false, namev4: nil, namev6: nil)
    xpc_dictionary_set_bool(wrongNamev4, "namev4", true)
    #expect(
      VendorCharonControlWireCodec.connectionEvent(wrongNamev4)
        == .unexpectedDictionary)

    let wrongNamev6 = tunnelNameObject(success: true, namev4: nil, namev6: nil)
    xpc_dictionary_set_int64(wrongNamev6, "namev6", 6)
    #expect(
      VendorCharonControlWireCodec.connectionEvent(wrongNamev6)
        == .unexpectedDictionary)
  }

  @Test func malformedStatusDictionariesAreRejected() {
    let extra = statusObject(name: "synthetic", type: 1, phase: 2, state: 5)
    xpc_dictionary_set_bool(extra, "extra", true)
    #expect(VendorCharonControlWireCodec.connectionEvent(extra) == .unexpectedDictionary)

    let missing = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(missing, "name", "synthetic")
    xpc_dictionary_set_int64(missing, "type", 1)
    xpc_dictionary_set_int64(missing, "phase", 2)
    #expect(VendorCharonControlWireCodec.connectionEvent(missing) == .unexpectedDictionary)

    let wrongType = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(wrongType, "name", "opaque")
    xpc_dictionary_set_int64(wrongType, "type", 1)
    xpc_dictionary_set_string(wrongType, "phase", "2")
    xpc_dictionary_set_int64(wrongType, "state", 3)
    #expect(VendorCharonControlWireCodec.connectionEvent(wrongType) == .unexpectedDictionary)
  }

  @Test func onlyExactEmptyReplyIsTransportAcknowledgement() {
    let empty = xpc_dictionary_create(nil, nil, 0)
    #expect(
      VendorCharonControlWireCodec.replyEvent(empty)
        == .emptyAcknowledgement)

    xpc_dictionary_set_bool(empty, "success", true)
    #expect(VendorCharonControlWireCodec.replyEvent(empty) == .unexpectedPayload)

    let array = xpc_array_create(nil, 0)
    #expect(VendorCharonControlWireCodec.replyEvent(array) == .unexpectedPayload)
  }
  @Test func ncRouteToggleCopiesTunnelNameAndUsesExactOfficialWireShape() throws {
    #expect(
      VendorCharonNCRouteToggleContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "updown_nc"),
      ])
    var context: VendorCharonNCRouteToggleContext?
    try ControlSnapshotFixture().snapshot().withEncodedStartMessage { start in
      context = VendorCharonControlWireCodec.ncRouteToggleContext(
        copyingTunnelNameFromStartRequest: start,
        selectedTunnelIndex: 0
      )
    }

    for enabled in [true, false] {
      let request = VendorCharonControlWireCodec.makeNCRouteToggleRequest(
        context: try #require(context),
        enabled: enabled
      )
      #expect(hasExactKeys(request, ["type", "rpc", "updown", "tunnel-name"]))
      #expect(try string(request, "type") == "rpc")
      #expect(try string(request, "rpc") == "updown_nc")
      #expect(xpc_dictionary_get_bool(request, "updown") == enabled)
      #expect(try string(request, "tunnel-name") == "synthetic-tunnel")
    }
  }

  @Test func ncRouteToggleContextUsesSelectedIndexAndRejectsInvalidSelection() throws {
    try ControlSnapshotFixture().snapshot(
      tunnelNames: ["synthetic-tunnel-first", "synthetic-tunnel-second"]
    ).withEncodedStartMessage { start in
      for (index, expectedName) in [
        (0, "synthetic-tunnel-first"),
        (1, "synthetic-tunnel-second"),
      ] {
        let context = try #require(
          VendorCharonControlWireCodec.ncRouteToggleContext(
            copyingTunnelNameFromStartRequest: start,
            selectedTunnelIndex: index
          )
        )
        let request = VendorCharonControlWireCodec.makeNCRouteToggleRequest(
          context: context,
          enabled: true
        )
        #expect(try string(request, "tunnel-name") == expectedName)
      }
      #expect(
        VendorCharonControlWireCodec.ncRouteToggleContext(
          copyingTunnelNameFromStartRequest: start,
          selectedTunnelIndex: -1
        ) == nil
      )
      #expect(
        VendorCharonControlWireCodec.ncRouteToggleContext(
          copyingTunnelNameFromStartRequest: start,
          selectedTunnelIndex: 2
        ) == nil
      )

      let tunnels = try array(start, "tunnels")
      xpc_array_set_value(tunnels, 1, xpc_string_create("wrong-type"))
      #expect(
        VendorCharonControlWireCodec.ncRouteToggleContext(
          copyingTunnelNameFromStartRequest: start,
          selectedTunnelIndex: 1
        ) == nil
      )
    }
  }

  @Test func onlyExactBooleanNCRouteToggleReplyIsDecoded() {
    for success in [true, false] {
      let reply = xpc_dictionary_create(nil, nil, 0)
      xpc_dictionary_set_bool(reply, "updown_nc_success", success)
      #expect(
        VendorCharonControlWireCodec.replyEvent(reply)
          == .ncRouteToggleAcknowledgement(success: success))
    }

    let extra = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_bool(extra, "updown_nc_success", true)
    xpc_dictionary_set_bool(extra, "extra", true)
    #expect(VendorCharonControlWireCodec.replyEvent(extra) == .unexpectedPayload)

    let wrongType = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(wrongType, "updown_nc_success", "true")
    #expect(VendorCharonControlWireCodec.replyEvent(wrongType) == .unexpectedPayload)
  }

}

private func statusObject(
  name: String,
  type: Int64,
  phase: Int64,
  state: Int64
) -> xpc_object_t {
  let result = xpc_dictionary_create(nil, nil, 0)
  xpc_dictionary_set_string(result, "name", name)
  xpc_dictionary_set_int64(result, "type", type)
  xpc_dictionary_set_int64(result, "phase", phase)
  xpc_dictionary_set_int64(result, "state", state)
  return result
}

private func tunnelNameObject(
  success: Bool,
  namev4: String?,
  namev6: String?
) -> xpc_object_t {
  let result = xpc_dictionary_create(nil, nil, 0)
  xpc_dictionary_set_bool(result, "get_tun_name_success", success)
  if let namev4 { xpc_dictionary_set_string(result, "namev4", namev4) }
  if let namev6 { xpc_dictionary_set_string(result, "namev6", namev6) }
  return result
}

private func statusSignal(
  _ event: VendorCharonControlConnectionEvent
) -> VendorCharonStatusSignal? {
  guard case .status(let signal) = event else { return nil }
  return signal
}
