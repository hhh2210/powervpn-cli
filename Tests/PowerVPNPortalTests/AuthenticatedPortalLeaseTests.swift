import Testing

@testable import PowerVPNPortal

@Suite struct AuthenticatedPortalLeaseTests {
  @Test func acquisitionDoesNotLogoutUntilLeaseIsExplicitlyClosed() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: transport,
      sleeper: SyntheticPortalSleeper()
    )

    let result = await workflow.acquire(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )
    let lease: AuthenticatedPortalLease
    switch result {
    case .acquired(let acquired): lease = acquired
    case .rejected(let report):
      Issue.record("unexpected acquisition rejection: \(report.status)")
      return
    }

    #expect(await transport.snapshots().map(\.method) == [.post, .get])
    #expect(!lease.snapshot.isErased)
    #expect(lease.snapshot.isAccessible)
    #expect(await lease.logoutAndErase() == PortalLeaseLogoutResult(status: .accepted))
    #expect(lease.snapshot.isErased)
    #expect(!lease.snapshot.isAccessible)
    #expect(await lease.logoutAndErase() == PortalLeaseLogoutResult(status: .alreadyClosed))
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
  }

  @Test func concurrentCloseCallsSendExactlyOneLogout() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let workflow = try PortalLoginWorkflow(
      factory: try syntheticRequestFactory(),
      transport: transport,
      sleeper: SyntheticPortalSleeper()
    )
    let result = await workflow.acquire(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )
    guard case .acquired(let lease) = result else {
      Issue.record("unexpected acquisition rejection")
      return
    }

    let statuses = await withTaskGroup(
      of: PortalLeaseLogoutStatus.self,
      returning: [PortalLeaseLogoutStatus].self
    ) { group in
      for _ in 0..<8 {
        group.addTask { await lease.logoutAndErase().status }
      }
      var statuses: [PortalLeaseLogoutStatus] = []
      for await status in group { statuses.append(status) }
      return statuses
    }

    #expect(statuses.count { $0 == .accepted } == 1)
    #expect(statuses.count { $0 == .alreadyClosed } == 7)
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
    #expect(await transport.allOwnedRequestMaterialErased())
    #expect(await transport.allOwnedResponseMaterialErased())
  }

  @Test func acquisitionFailurePerformsOneCleanupLogout() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(
        status: 200,
        body: "<ROOT><RESPONSE><ERROR><code>1</code></ERROR></RESPONSE></ROOT>"
      ),
      .response(status: 200, body: ""),
    ])
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: transport,
      sleeper: SyntheticPortalSleeper()
    )

    let result = await workflow.acquire(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )
    switch result {
    case .acquired:
      Issue.record("expected acquisition rejection")
    case .rejected(let report):
      #expect(report.status == .resourceListRejected)
      #expect(report.operations.logoutRequested)
      #expect(report.operations.logoutAccepted)
      #expect(report.ownedMaterial.sessionMaterialErased)
    }
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
  }

  @Test func logoutTimeoutStillErasesLocalLeaseMaterial() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .suspendUntilCancelled,
    ])
    let workflow = try PortalLoginWorkflow(
      factory: syntheticRequestFactory(),
      transport: transport,
      sleeper: SyntheticPortalSleeper(),
      logoutBounder: TimedDetachedPortalLogoutBounder(timeoutNanoseconds: 1_000_000)
    )
    let result = await workflow.acquire(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )
    guard case .acquired(let lease) = result else {
      Issue.record("unexpected acquisition rejection")
      return
    }

    #expect(await lease.logoutAndErase() == PortalLeaseLogoutResult(status: .timedOut))
    #expect(lease.snapshot.isErased)
    #expect(await lease.logoutAndErase() == PortalLeaseLogoutResult(status: .alreadyClosed))
    #expect(await transport.allOwnedRequestMaterialErased())
    #expect(await transport.allOwnedResponseMaterialErased())
  }

  @Test func rejectedAndCancelledLogoutBothCloseAndEraseTheLease() async throws {
    let cases: [(SyntheticTransportStep, PortalLeaseLogoutResult)] = [
      (
        .response(status: 500, body: ""),
        PortalLeaseLogoutResult(status: .rejected, failureClass: .completedRemoteExchange)
      ),
      (
        .failure(.unavailable),
        PortalLeaseLogoutResult(status: .rejected, failureClass: .transportFailed)
      ),
      (.failure(.cancelled), PortalLeaseLogoutResult(status: .cancelled)),
    ]
    for (logoutStep, expected) in cases {
      let transport = SyntheticPortalTransport([
        .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
        .response(status: 200, body: acceptedResourceXML),
        logoutStep,
      ])
      let workflow = try PortalLoginWorkflow(
        factory: try syntheticRequestFactory(),
        transport: transport,
        sleeper: SyntheticPortalSleeper()
      )
      let result = await workflow.acquire(
        credentials: try syntheticCredentials(),
        platformSerial: try syntheticSerial()
      )
      guard case .acquired(let lease) = result else {
        Issue.record("unexpected acquisition rejection")
        continue
      }

      #expect(await lease.logoutAndErase() == expected)
      #expect(lease.snapshot.isErased)
      #expect(await lease.logoutAndErase() == PortalLeaseLogoutResult(status: .alreadyClosed))
      #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
      #expect(await transport.allOwnedRequestMaterialErased())
      #expect(await transport.allOwnedResponseMaterialErased())
    }
  }

  @Test func erasedSessionClassifiesLogoutConstructionFailure() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let factory = try syntheticRequestFactory()
    let workflow = try PortalLoginWorkflow(
      factory: factory,
      transport: transport,
      sleeper: SyntheticPortalSleeper()
    )
    let result = await workflow.acquire(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )
    guard case .acquired(let lease) = result else {
      Issue.record("unexpected acquisition rejection")
      return
    }
    factory.eraseSession()

    #expect(
      await lease.logoutAndErase()
        == PortalLeaseLogoutResult(
          status: .rejected,
          failureClass: .requestConstructionFailed
        )
    )
    #expect(lease.snapshot.isErased)
    // The logout request was never constructed, so no third wire request
    // exists to erase.
    #expect(await transport.snapshots().map(\.method) == [.post, .get])
  }
}
