import Testing

@testable import PowerVPNPortal

@Suite struct PortalLoginWorkflowTests {
  @Test func exactHappyPathOrderWireDelayAndErasure() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .response(status: 200, body: ""),
    ])
    let sleeper = SyntheticPortalSleeper()
    let factory = try syntheticRequestFactory()
    let workflow = try PortalLoginWorkflow(
      factory: factory,
      transport: transport,
      sleeper: sleeper
    )
    let credentialErase = SyntheticEraseObserver()
    let serialErase = SyntheticEraseObserver()
    let report = await workflow.run(
      credentials: try syntheticCredentials(observer: credentialErase),
      platformSerial: try syntheticSerial(observer: serialErase)
    )

    #expect(report.status == .accepted)
    #expect(report.transactionAccepted)
    #expect(report.operations == fullyAcceptedOperations)
    #expect(report.ownedMaterial.credentialsErased)
    #expect(report.ownedMaterial.requestBodiesErased)
    #expect(report.ownedMaterial.responseBodiesErased)
    #expect(report.ownedMaterial.sessionMaterialErased)
    #expect(credentialErase.result.count == 2)
    #expect(credentialErase.result.allZero)
    #expect(serialErase.result.count == 1)
    #expect(serialErase.result.allZero)
    #expect(factory.retainedSessionByteCount == 0)

    let snapshots = await transport.snapshots()
    #expect(snapshots.map(\.method) == [.post, .get, .get, .post])
    #expect(
      snapshots.map(\.url) == [
        "https://166.111.143.19:4443/vpn/user/auth/password",
        "https://166.111.143.19:4443/vpn/user/portal/intergration.xml?version=2.0",
        "https://166.111.143.19:4443/vpn/user/check/session?key=hostid",
        "https://166.111.143.19:4443/vpn/user/logout",
      ]
    )
    #expect(snapshots[0].contentType == "text/xml")
    #expect(snapshots.dropFirst().allSatisfy { $0.contentType == nil })
    #expect(snapshots[0].cookie == " VSG_LANGUAGE=zh_CN; ")
    #expect(
      snapshots.dropFirst().allSatisfy {
        $0.cookie == authenticatedCookie
      }
    )
    #expect(snapshots[0].body == passwordBody)
    #expect(snapshots.dropFirst().allSatisfy { $0.body == nil })
    #expect(snapshots.allSatisfy { $0.accept == "*/*" })
    #expect(snapshots.allSatisfy { $0.userAgent == syntheticUserAgent })
    #expect(await sleeper.sleeps() == [60])
    #expect(await transport.remainingStepCount() == 0)
    #expect(await transport.allOwnedRequestMaterialErased())
    #expect(await transport.allOwnedResponseMaterialErased())
  }

  @Test func challengeAndCredentialRejectionNeverStoreSessionOrLogout() async throws {
    for (xml, status) in [
      (loginXML("0x66600011"), PortalLoginStatus.challengeRequired),
      (loginXML("0x66600010"), PortalLoginStatus.loginRejected),
    ] {
      let transport = SyntheticPortalTransport([
        .response(status: 200, body: xml, setCookie: syntheticSessionCookie)
      ])
      let sleeper = SyntheticPortalSleeper()
      let factory = try syntheticRequestFactory()
      let report = try await syntheticLoginWorkflow(factory, transport, sleeper).run(
        credentials: syntheticCredentials(),
        platformSerial: syntheticSerial()
      )
      #expect(report.status == status)
      #expect(report.operations.loginRequested)
      #expect(!report.operations.loginAccepted)
      #expect(!report.operations.logoutRequested)
      #expect(factory.retainedSessionByteCount == 0)
      #expect(await transport.snapshots().count == 1)
      #expect(await sleeper.sleeps().isEmpty)
    }
  }

  @Test func resourceFailureTriggersExactlyOneLogoutWithoutDelay() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(
        status: 200,
        body: "<ROOT><RESPONSE><RESULT><code>0x80000020</code></RESULT></RESPONSE></ROOT>"
      ),
      .response(status: 200, body: ""),
    ])
    let sleeper = SyntheticPortalSleeper()
    let factory = try syntheticRequestFactory()
    let report = try await syntheticLoginWorkflow(factory, transport, sleeper).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )
    #expect(report.status == .resourceListRejected)
    #expect(report.operations.loginAccepted)
    #expect(report.operations.resourceListRequested)
    #expect(!report.operations.resourceListAccepted)
    #expect(report.operations.logoutRequested)
    #expect(report.operations.logoutAccepted)
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
    #expect(await sleeper.sleeps().isEmpty)
  }

  @Test func exactInvalidSessionTriggersOneCleanupLogout() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: invalidSessionXML),
      .response(status: 200, body: ""),
    ])
    let sleeper = SyntheticPortalSleeper()
    let report = try await syntheticLoginWorkflow(
      try syntheticRequestFactory(), transport, sleeper
    ).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )
    #expect(report.status == .sessionRejected)
    #expect(report.operations.sessionCheckRequested)
    #expect(!report.operations.sessionCheckAccepted)
    #expect(report.operations.logoutRequested)
    #expect(report.operations.logoutAccepted)
    #expect(await sleeper.sleeps() == [60])
    #expect(await transport.snapshots().count == 4)
  }

  @Test func logoutFailureIsNotRetried() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .response(status: 500, body: ""),
    ])
    let report = try await syntheticLoginWorkflow(
      try syntheticRequestFactory(), transport, SyntheticPortalSleeper()
    ).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )
    #expect(report.status == .logoutRejected)
    #expect(report.operations.logoutRequested)
    #expect(!report.operations.logoutAccepted)
    #expect(await transport.snapshots().count == 4)
    #expect(await transport.remainingStepCount() == 0)
  }

  @Test func cancellationDuringDelayStillAttemptsOneBoundedLogout() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let sleeper = SyntheticPortalSleeper(.cancel)
    let report = try await syntheticLoginWorkflow(
      try syntheticRequestFactory(), transport, sleeper
    ).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )
    #expect(report.status == .cancelled)
    #expect(report.operations.resourceListAccepted)
    #expect(!report.operations.sessionCheckRequested)
    #expect(report.operations.logoutRequested)
    #expect(report.operations.logoutAccepted)
    #expect(await sleeper.sleeps() == [60])
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
  }

  @Test func transportFailureAtLoginDoesNotRetryOrLogout() async throws {
    let transport = SyntheticPortalTransport([.failure(.timedOut)])
    let report = try await syntheticLoginWorkflow(
      try syntheticRequestFactory(), transport, SyntheticPortalSleeper()
    ).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )
    #expect(report.status == .transportRejected)
    #expect(report.operations.loginRequested)
    #expect(!report.operations.loginAccepted)
    #expect(!report.operations.logoutRequested)
    #expect(await transport.snapshots().count == 1)
  }

  private func loginXML(_ code: String) -> String {
    "<ROOT><RESPONSE><RESULT><code>\(code)</code></RESULT></RESPONSE></ROOT>"
  }

  private var passwordBody: String {
    "encode='1'&hardware_hash=SERIAL&password=cGFzcw==&terminal_type=mac&type=app&username=dXNlcg=="
  }

  private var authenticatedCookie: String {
    "VSG_SESSIONID=synthetic ORIGINURL=https://166.111.143.19:4443/vpn/user/auth/password;  VSG_LANGUAGE=zh_CN; "
  }

  private var syntheticUserAgent: String {
    "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X synthetic-os)"
  }

  private var fullyAcceptedOperations: PortalOperationEvidence {
    PortalOperationEvidence(
      loginRequested: true,
      loginAccepted: true,
      sessionCheckRequested: true,
      sessionCheckAccepted: true,
      resourceListRequested: true,
      resourceListAccepted: true,
      logoutRequested: true,
      logoutAccepted: true
    )
  }
}
