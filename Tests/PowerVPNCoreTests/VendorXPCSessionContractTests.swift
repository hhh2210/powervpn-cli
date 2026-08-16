import Testing

@testable import PowerVPNCore

@Suite struct VendorXPCSessionContractTests {
  @Test func fixedServiceAndExactPeerRequirementAreLocked() {
    #expect(VendorXPCSessionContract.serviceName == "com.leadsec.charon-xpc")
    #expect(
      VendorXPCSessionContract.peerRequirement
        == "anchor apple generic and identifier \"com.leadsec.charon-xpc\" and "
        + "(certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or "
        + "certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and "
        + "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and "
        + "certificate leaf[subject.OU] = M75ATYZ92T)"
    )
    #expect(
      SystemVendorCharonControlConnectionDriver.serviceName
        == VendorXPCSessionContract.serviceName
    )
    #expect(
      SystemVendorCharonEmergencyConnectionDriver.serviceName
        == VendorXPCSessionContract.serviceName
    )
  }

  @Test func runtimePreflightIsClosedAndPerformsNoSessionSend() {
    if #available(macOS 14.4, *) {
      #expect(VendorXPCSessionContract.runtimePreflight() == .accepted)
    } else {
      #expect(VendorXPCSessionContract.runtimePreflight() == .unsupportedOS)
    }
  }

  @Test func richReplyFailureMapsToReplyUnavailable() {
    #expect(VendorXPCSessionContract.replyFailureEvent == .replyUnavailable)
  }
}
