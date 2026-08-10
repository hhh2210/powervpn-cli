import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AuthorizedResourceProviderTests {
  @Test func explicitNativePortalProviderPreservesTLSRejection() async {
    let provider = ProductM2PortalAdapter {
      .rejected(
        PortalLoginReport(
          status: .tlsRejected,
          operations: PortalOperationEvidence(
            loginRequested: true,
            loginAccepted: false,
            sessionCheckRequested: false,
            sessionCheckAccepted: false,
            resourceListRequested: false,
            resourceListAccepted: false,
            logoutRequested: false,
            logoutAccepted: false
          ),
          ownedMaterial: PortalOwnedMaterialEvidence(
            credentialsErased: true,
            requestBodiesErased: true,
            responseBodiesErased: true,
            sessionMaterialErased: true
          )
        )
      )
    }

    switch await provider.acquire() {
    case .rejected(let source, let failure, let contacted):
      #expect(source == .nativePortal)
      #expect(failure == .tlsRejected)
      #expect(contacted)
    case .acquired:
      Issue.record("TLS rejection must not become an acquired authorization")
    }
  }

  @Test func coordinatorReportPreservesExplicitNativeTLSRejection() async {
    let trace = ProductM2TestTrace()
    let dependencies = ProductM2ConnectOnceDependencies(
      controlRuntimePreflightAccepted: { true },
      observeGeneration: { m2ColdGeneration },
      preflightAccepted: { _ in true },
      captureNetworkBaseline: { window, selectedRoutes in
        trace.nextBaseline(window: window, selectedRoutes: selectedRoutes)
      },
      baselineStable: { _, _ in false },
      assessActiveConnection: { _, _ in .unavailable },
      authorizationSource: .nativePortal,
      acquireAuthorization: {
        .rejected(
          source: .nativePortal,
          failure: .tlsRejected,
          serverContactRequested: true
        )
      },
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      proveFreshSSH: { target in m2SSHEvidence(.rejected, target: target) },
      verifyCleanup: { _, _, _, _ in m2CompleteCleanup }
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .authorizationAcquisitionRejected)
    #expect(report.authorizationSource == .nativePortal)
    #expect(report.authorizationAcquisition == .rejected)
    #expect(report.authorizationFailure == .tlsRejected)
    #expect(report.serverContactRequested)
    #expect(!report.helperMutationRequested)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("ssh") == 0)
  }

  @Test func everyPortalStatusHasAClosedValueFreeFailure() {
    let expected: [(PortalLoginStatus, ProductM2AuthorizationFailure)] = [
      (.accepted, .accepted),
      (.configurationRejected, .configurationRejected),
      (.credentialInputRejected, .credentialInputRejected),
      (.transportRejected, .transportRejected),
      (.tlsRejected, .tlsRejected),
      (.redirectRejected, .redirectRejected),
      (.loginRejected, .loginRejected),
      (.challengeRequired, .challengeRequired),
      (.loginResponseRejected, .loginResponseRejected),
      (.sessionRejected, .sessionRejected),
      (.resourceListRejected, .resourceListRejected),
      (.authenticatedSnapshotRejected, .authenticatedSnapshotRejected),
      (.logoutRejected, .logoutRejected),
      (.cancelled, .cancelled),
      (.internalFailure, .internalFailure),
    ]
    for (status, failure) in expected {
      #expect(ProductM2AuthorizationFailure(status) == failure)
    }
  }

  @Test func unavailableVendorProviderIsLocalAndExplicit() async {
    let provider = ProductM2UnavailableVendorOnceProvider()
    #expect(provider.source == .vendorOnce)
    #expect(provider.availabilityFailure == .providerUnavailable)
    switch await provider.acquire() {
    case .rejected(let source, let failure, let contacted):
      #expect(source == .vendorOnce)
      #expect(failure == .providerUnavailable)
      #expect(!contacted)
    case .acquired:
      Issue.record("unavailable provider must fail closed")
    }
  }
}
