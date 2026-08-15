import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AuthorizedResourceProviderTests {
  @Test func explicitNativePortalProviderPreservesTLSRejection() async {
    let provider = ProductM2PortalAdapter { _ in
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

    switch await provider.beginAcquire(budget: m2TestBudget().authorization).result() {
    case .rejected(let source, let failure, let cleanup):
      #expect(source == .nativePortal)
      #expect(failure == .tlsRejected)
      #expect(cleanup.serverContactRequested)
      #expect(cleanup.ownedMaterialErased)
      #expect(cleanup.outcome == .notRequired)
    case .acquired:
      Issue.record("TLS rejection must not become an acquired authorization")
    }
  }

  @Test func coordinatorReportPreservesExplicitNativeTLSRejection() async {
    let trace = ProductM2TestTrace()
    let dependencies = ProductM2ConnectOnceDependencies(
      acquireMutationLease: { ProductM2TestMutationLease() },
      controlRuntimePreflightAccepted: { true },
      observeGeneration: { _ in m2ColdGeneration },
      preflightAccepted: { _, _ in true },
      captureNetworkBaseline: { window, selectedRoutes, _ in
        trace.nextBaseline(window: window, selectedRoutes: selectedRoutes)
      },
      baselineStable: { _, _ in false },
      assessActiveConnection: { _, _ in .unavailable },
      authorizationSource: .nativePortal,
      beginAuthorization: { _ in
        m2AuthorizationAttempt(
          .rejected(
            source: .nativePortal,
            failure: .tlsRejected,
            cleanup: ProductM2AuthorizationCloseReceipt(
              outcome: .notRequired,
              ownedMaterialErased: true,
              sourceCloseRequested: false,
              serverContactRequested: true
            ))
        )
      },
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      proveFreshSSH: { target, _ in m2SSHEvidence(.rejected, target: target) },
      verifyCleanup: { _, _, _, _, _ in m2CompleteCleanup }
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
    #expect(report.authorizationOwnedMaterialErased)
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

  @Test func unavailableNativePortalProviderIsLocalAndExplicit() async {
    let provider = ProductM2UnavailableNativePortalProvider()
    #expect(provider.source == .nativePortal)
    #expect(provider.availabilityFailure == .providerUnavailable)
    switch await provider.beginAcquire(budget: m2TestBudget().authorization).result() {
    case .rejected(let source, let failure, let cleanup):
      #expect(source == .nativePortal)
      #expect(failure == .providerUnavailable)
      #expect(!cleanup.serverContactRequested)
      #expect(cleanup.ownedMaterialErased)
      #expect(cleanup.outcome == .notRequired)
    case .acquired:
      Issue.record("unavailable provider must fail closed")
    }
  }

  @Test func rejectedAcquisitionWithoutErasureCannotPassCleanup() async {
    let trace = ProductM2TestTrace()
    let dependencies = ProductM2ConnectOnceDependencies(
      acquireMutationLease: { ProductM2TestMutationLease() },
      controlRuntimePreflightAccepted: { true },
      observeGeneration: { _ in m2ColdGeneration },
      preflightAccepted: { _, _ in true },
      captureNetworkBaseline: { window, selectedRoutes, _ in
        trace.nextBaseline(window: window, selectedRoutes: selectedRoutes)
      },
      baselineStable: { _, _ in true },
      assessActiveConnection: { _, _ in .unavailable },
      authorizationSource: .nativePortal,
      beginAuthorization: { _ in
        m2AuthorizationAttempt(
          .rejected(
            source: .nativePortal,
            failure: .internalFailure,
            cleanup: ProductM2AuthorizationCloseReceipt(
              outcome: .notRequired,
              ownedMaterialErased: false,
              sourceCloseRequested: false,
              serverContactRequested: false
            ))
        )
      },
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      proveFreshSSH: { target, _ in m2SSHEvidence(.rejected, target: target) },
      verifyCleanup: { _, _, _, _, _ in m2CompleteCleanup }
    )

    let report = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(report.outcome == .cleanupUnproven)
    #expect(report.firstBadEvent == .authorizationAcquisitionRejected)
    #expect(!report.authorizationOwnedMaterialErased)
    #expect(!report.cleanupVerified)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("ssh") == 0)
  }

  @Test func rejectedPortalLogoutCannotPassCleanup() async {
    let report = PortalLoginReport(
      status: .resourceListRejected,
      operations: PortalOperationEvidence(
        loginRequested: true,
        loginAccepted: true,
        sessionCheckRequested: false,
        sessionCheckAccepted: false,
        resourceListRequested: true,
        resourceListAccepted: false,
        logoutRequested: true,
        logoutAccepted: false
      ),
      ownedMaterial: PortalOwnedMaterialEvidence(
        credentialsErased: true,
        requestBodiesErased: true,
        responseBodiesErased: true,
        sessionMaterialErased: true
      )
    )
    let provider = ProductM2PortalAdapter { _ in .rejected(report) }
    let trace = ProductM2TestTrace()
    let dependencies = ProductM2ConnectOnceDependencies(
      acquireMutationLease: { ProductM2TestMutationLease() },
      controlRuntimePreflightAccepted: { true },
      observeGeneration: { _ in m2ColdGeneration },
      preflightAccepted: { _, _ in true },
      captureNetworkBaseline: { window, selectedRoutes, _ in
        trace.nextBaseline(window: window, selectedRoutes: selectedRoutes)
      },
      baselineStable: { _, _ in true },
      assessActiveConnection: { _, _ in .unavailable },
      authorizationSource: .nativePortal,
      beginAuthorization: provider.beginAcquire,
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      proveFreshSSH: { target, _ in m2SSHEvidence(.rejected, target: target) },
      verifyCleanup: { _, _, _, _, _ in m2CompleteCleanup }
    )

    let result = await ProductM2ConnectOnceCoordinator(
      dependencies: dependencies
    ).run(
      ProductM2ConnectRequest(resourceDisplayName: "Campus NC", sshTarget: .thu21)
    )

    #expect(result.outcome == .cleanupUnproven)
    #expect(result.authorizationFailure == .resourceListRejected)
    #expect(result.authorizationClose == .rejected)
    #expect(result.authorizationOwnedMaterialErased)
    #expect(result.serverContactRequested)
    #expect(!result.cleanupVerified)
    #expect(trace.count("begin_start") == 0)
    #expect(trace.count("ssh") == 0)
  }
}

private func m2AuthorizationAttempt(
  _ result: ProductM2AuthorizedResourceAcquisition
) -> ProductM2AuthorizationAttempt {
  ProductM2AuthorizationAttempt(
    source: .nativePortal,
    operation: { result },
    cancel: {}
  )
}
