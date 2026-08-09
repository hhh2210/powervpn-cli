import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalLoginReportTests {
  @Test func acceptedReportRequiresEveryOperationAndErasureGate() throws {
    let report = acceptedReport()

    #expect(report.transactionAccepted)
    let encoded = try JSONEncoder().encode(report)
    let root = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    #expect(
      Set(root.keys) == [
        "schemaVersion", "mode", "status", "operations", "ownedMaterial", "safety",
        "transactionAccepted",
      ]
    )
    #expect(root["status"] as? String == "accepted")
    #expect(String(decoding: encoded, as: UTF8.self).contains("166.111") == false)
    #expect(String(decoding: encoded, as: UTF8.self).contains("sessionid") == false)
  }

  @Test(arguments: [
    PortalLoginStatus.configurationRejected,
    .credentialInputRejected,
    .transportRejected,
    .tlsRejected,
    .redirectRejected,
    .loginRejected,
    .challengeRequired,
    .loginResponseRejected,
    .sessionRejected,
    .resourceListRejected,
    .logoutRejected,
    .cancelled,
    .internalFailure,
  ])
  func nonAcceptedStatusCannotPass(_ status: PortalLoginStatus) {
    let baseline = acceptedReport()
    let report = PortalLoginReport(
      status: status,
      operations: baseline.operations,
      ownedMaterial: baseline.ownedMaterial
    )
    #expect(!report.transactionAccepted)
  }

  @Test func missingOperationOrErasureCannotPass() {
    let operations = PortalOperationEvidence(
      loginRequested: true,
      loginAccepted: true,
      sessionCheckRequested: true,
      sessionCheckAccepted: true,
      resourceListRequested: true,
      resourceListAccepted: true,
      logoutRequested: true,
      logoutAccepted: false
    )
    let material = PortalOwnedMaterialEvidence(
      credentialsErased: true,
      requestBodiesErased: true,
      responseBodiesErased: true,
      sessionMaterialErased: true
    )
    #expect(
      !PortalLoginReport(
        status: .accepted,
        operations: operations,
        ownedMaterial: material
      ).transactionAccepted
    )

    let notErased = PortalOwnedMaterialEvidence(
      credentialsErased: true,
      requestBodiesErased: true,
      responseBodiesErased: false,
      sessionMaterialErased: true
    )
    #expect(
      !PortalLoginReport(
        status: .accepted,
        operations: acceptedReport().operations,
        ownedMaterial: notErased
      ).transactionAccepted
    )
  }

  private func acceptedReport() -> PortalLoginReport {
    PortalLoginReport(
      status: .accepted,
      operations: PortalOperationEvidence(
        loginRequested: true,
        loginAccepted: true,
        sessionCheckRequested: true,
        sessionCheckAccepted: true,
        resourceListRequested: true,
        resourceListAccepted: true,
        logoutRequested: true,
        logoutAccepted: true
      ),
      ownedMaterial: PortalOwnedMaterialEvidence(
        credentialsErased: true,
        requestBodiesErased: true,
        responseBodiesErased: true,
        sessionMaterialErased: true
      )
    )
  }
}
