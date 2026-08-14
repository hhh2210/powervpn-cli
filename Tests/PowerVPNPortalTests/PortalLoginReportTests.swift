import CPortalCurl
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
    #expect(root["schemaVersion"] as? Int == 2)
    #expect(root["status"] as? String == "accepted")
    let safety = try #require(root["safety"] as? [String: Any])
    #expect(safety["trustMode"] as? String == "operator_approved_tofu")
    #expect(safety["releaseReady"] as? Bool == false)
    #expect(safety["fixedSPKIPinRequired"] as? Bool == true)
    #expect(safety["systemTrustRequired"] as? Bool == false)
    #expect(safety["endpointSource"] as? String == "operator_approved_fixed_local_mvp")
    #expect(safety["appOwnedSecureBuffersErasureObserved"] as? Bool == true)
    #expect(safety["swiftAndFoundationBridgeCopiesErasureClaimed"] as? Bool == false)
    #expect(safety["appOwnedCopiesErasureClaimed"] == nil)
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

  @Test func cFailuresKeepExactValueFreeCategoriesAndBoundedHeaderCounters() throws {
    let categories: [(pvcurl_status_t, PortalTransportFailureCategory)] = [
      (PVCURL_STATUS_INVALID_ARGUMENT, .invalidRequest),
      (PVCURL_STATUS_SETUP_FAILED, .setupFailed),
      (PVCURL_STATUS_TRUST_REJECTED, .trustRejected),
      (PVCURL_STATUS_REDIRECT_REJECTED, .redirectRejected),
      (PVCURL_STATUS_AUTHENTICATION_REJECTED, .httpAuthenticationRejected),
      (PVCURL_STATUS_HEADER_FRAMING_REJECTED, .headerFramingRejected),
      (PVCURL_STATUS_RESPONSE_TOO_LARGE, .responseTooLarge),
      (PVCURL_STATUS_CANCELLED, .cancelled),
      (PVCURL_STATUS_TIMED_OUT, .timedOut),
      (PVCURL_STATUS_UNAVAILABLE, .unavailable),
    ]
    for (status, category) in categories {
      let failure = try #require(CPortalCurlDriver.normalizedFailure(status))
      #expect(failure.evidence.category == category)
      #expect(failure.evidence.setCookieFieldCount == nil)
      #expect(failure.evidence.setCookieWireSelection == nil)
      #expect(failure.evidence.duplicateSetCookieRejected == nil)
    }

    var authenticationDiagnostics = pvcurl_transfer_diagnostics_t()
    authenticationDiagnostics.set_cookie_selection =
      PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS
    authenticationDiagnostics.response_headers_observed = true
    let authentication = try #require(
      CPortalCurlDriver.normalizedFailure(
        PVCURL_STATUS_AUTHENTICATION_REJECTED,
        diagnostics: authenticationDiagnostics
      ))
    #expect(authentication.evidence.category == .httpAuthenticationRejected)
    #expect(authentication.evidence.setCookieFieldCount == 0)
    #expect(authentication.evidence.setCookieWireSelection == .lastFieldWins)
    #expect(authentication.evidence.duplicateSetCookieRejected == false)

    let oversized = try #require(
      CPortalCurlDriver.normalizedFailure(
        PVCURL_STATUS_RESPONSE_TOO_LARGE,
        diagnostics: authenticationDiagnostics
      ))
    #expect(oversized.evidence.category == .responseTooLarge)
    #expect(oversized.evidence.setCookieFieldCount == 0)
    #expect(oversized.evidence.setCookieWireSelection == .lastFieldWins)
    #expect(oversized.evidence.duplicateSetCookieRejected == false)
  }

  @Test func malformedFinalCookieFailureSurvivesPasswordWorkflowWithoutValues() async throws {
    var diagnostics = pvcurl_transfer_diagnostics_t()
    diagnostics.status = PVCURL_STATUS_HEADER_FRAMING_REJECTED
    diagnostics.set_cookie_field_count = 2
    diagnostics.set_cookie_selection = PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS
    diagnostics.duplicate_set_cookie_rejected = false
    diagnostics.response_headers_observed = true
    let failure = try #require(
      CPortalCurlDriver.normalizedFailure(
        PVCURL_STATUS_HEADER_FRAMING_REJECTED,
        diagnostics: diagnostics
      ))
    let origin = try PortalHTTPOrigin(host: "166.111.143.19", port: 4_443)
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: CurlPortalTransport(
        allowedOrigin: origin,
        driver: FailingCurlPortalDriver(error: failure)
      ),
      sleeper: SyntheticPortalSleeper()
    )

    let report = try await workflow.run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )

    #expect(report.status == .transportRejected)
    #expect(report.transportFailure == failure.evidence)
    #expect(report.transportFailure?.setCookieFieldCount == 2)
    #expect(report.transportFailure?.setCookieWireSelection == .lastFieldWins)
    #expect(report.transportFailure?.duplicateSetCookieRejected == false)
    #expect(report.ownedMaterial.credentialsErased)
    #expect(report.ownedMaterial.requestBodiesErased)
    #expect(!failure.description.contains("Set-Cookie"))
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
