import Foundation
import Testing
@preconcurrency import XPC

@testable import PowerVPNCore

@Suite struct VendorCharonControlWireCodecTests {
  @Test func fixedServiceAndStopContractHaveNoInjectionSurface() {
    #expect(SystemVendorCharonControlConnectionDriver.serviceName == "com.leadsec.charon-xpc")
    #expect(
      VendorCharonStopContract.orderedFields == [
        VendorXPCRequestField(key: "type", value: "rpc"),
        VendorXPCRequestField(key: "rpc", value: "stop_connection"),
      ])

    let stop = VendorCharonControlWireCodec.makeStopRequest()
    #expect(hasExactKeys(stop, ["type", "rpc"]))
    #expect((try? string(stop, "type")) == "rpc")
    #expect((try? string(stop, "rpc")) == "stop_connection")
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
      VendorCharonControlWireCodec.replyEvent(empty, peerPID: 91)
        == .emptyAcknowledgement(peerPID: 91))

    xpc_dictionary_set_bool(empty, "success", true)
    #expect(VendorCharonControlWireCodec.replyEvent(empty, peerPID: 91) == .unexpectedPayload)

    let array = xpc_array_create(nil, 0)
    #expect(VendorCharonControlWireCodec.replyEvent(array, peerPID: 91) == .unexpectedPayload)
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

private func statusSignal(
  _ event: VendorCharonControlConnectionEvent
) -> VendorCharonStatusSignal? {
  guard case .status(let signal) = event else { return nil }
  return signal
}

private func retainedStrings(in value: Any) -> [String] {
  if let string = value as? String { return [string] }
  return Mirror(reflecting: value).children.flatMap { retainedStrings(in: $0.value) }
}
