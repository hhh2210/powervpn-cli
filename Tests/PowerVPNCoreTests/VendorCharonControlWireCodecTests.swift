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

  @Test func statusEventsAreClassifiedWithoutRetainingValues() {
    let empty = xpc_dictionary_create(nil, nil, 0)
    #expect(
      VendorCharonControlWireCodec.connectionEvent(empty) == .emptyDispatcherTail)

    let status = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(status, "name", "value-must-not-escape")
    xpc_dictionary_set_int64(status, "type", 1)
    xpc_dictionary_set_int64(status, "phase", 2)
    xpc_dictionary_set_int64(status, "state", 3)
    #expect(VendorCharonControlWireCodec.connectionEvent(status) == .status)

    xpc_dictionary_set_bool(status, "extra", true)
    #expect(VendorCharonControlWireCodec.connectionEvent(status) == .unexpectedDictionary)

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
