import Testing

@testable import PowerVPNPortal

@Suite struct PortalLoginCancellationTests {
  @Test func parentCancellationDuringDelayDoesNotSuppressCleanupLogout() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let sleeper = CancellableGatePortalSleeper()
    let workflow = try syntheticLoginWorkflow(
      try syntheticRequestFactory(), transport, sleeper
    )
    let credentials = try syntheticCredentials()
    let serial = try syntheticSerial()
    let task = Task {
      await workflow.run(credentials: credentials, platformSerial: serial)
    }

    var entered = false
    for _ in 0..<10_000 {
      if await sleeper.hasEntered() {
        entered = true
        break
      }
      await Task.yield()
    }
    #expect(entered)
    task.cancel()
    let report = await task.value

    #expect(report.status == .cancelled)
    #expect(report.operations.loginAccepted)
    #expect(report.operations.resourceListAccepted)
    #expect(report.operations.logoutRequested)
    #expect(report.operations.logoutAccepted)
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
    #expect(await transport.remainingStepCount() == 0)
  }

  @Test func cancellationAtEveryRequestStageNeverRetriesLoginOrLogout() async throws {
    let cases:
      [(
        steps: [SyntheticTransportStep], expectedCount: Int, cleanupAccepted: Bool
      )] = [
        ([.failure(.cancelled)], 1, false),
        (
          [
            .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
            .failure(.cancelled),
            .response(status: 200, body: ""),
          ], 3, true
        ),
        (
          [
            .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
            .response(status: 200, body: acceptedResourceXML),
            .failure(.cancelled),
            .response(status: 200, body: ""),
          ], 4, true
        ),
        (
          [
            .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
            .response(status: 200, body: acceptedResourceXML),
            .response(status: 200, body: acceptedSessionXML),
            .failure(.cancelled),
          ], 4, false
        ),
      ]

    for entry in cases {
      let transport = SyntheticPortalTransport(entry.steps)
      let report = try await syntheticLoginWorkflow(
        try syntheticRequestFactory(), transport, SyntheticPortalSleeper()
      ).run(
        credentials: syntheticCredentials(),
        platformSerial: syntheticSerial()
      )
      #expect(report.status == .cancelled)
      let snapshots = await transport.snapshots()
      #expect(snapshots.count == entry.expectedCount)
      #expect(snapshots.filter { $0.url.hasSuffix("/auth/password") }.count == 1)
      #expect(snapshots.filter { $0.url.hasSuffix("/logout") }.count <= 1)
      #expect(report.operations.logoutAccepted == entry.cleanupAccepted)
      #expect(await transport.remainingStepCount() == 0)
    }
  }

  @Test func acceptedCodeWithoutCookieFailsClosedAtRejectedResource() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML),
      .response(status: 200, body: ""),
      .response(status: 200, body: ""),
    ])
    let factory = try syntheticRequestFactory()
    let report = try await syntheticLoginWorkflow(
      factory, transport, SyntheticPortalSleeper()
    ).run(
      credentials: syntheticCredentials(),
      platformSerial: syntheticSerial()
    )

    #expect(report.status == .resourceListRejected)
    #expect(report.operations.loginAccepted)
    #expect(report.operations.resourceListRequested)
    #expect(!report.operations.resourceListAccepted)
    #expect(report.operations.logoutRequested)
    #expect(report.operations.logoutAccepted)
    let snapshots = await transport.snapshots()
    #expect(snapshots.map(\.method) == [.post, .get, .post])
    #expect(
      snapshots.map(\.cookie)
        == Array(repeating: " VSG_LANGUAGE=zh_CN; ", count: 3)
    )
    #expect(factory.retainedSessionByteCount == 0)
  }

  @Test func cleanupDeadlineReturnsAndErasesRequestWithoutRetry() async throws {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .suspendUntilCancelled,
    ])
    let shortBounder = TimedDetachedPortalLogoutBounder(timeoutNanoseconds: 1_000_000)
    let workflow = try syntheticLoginWorkflow(
      try syntheticRequestFactory(), transport, SyntheticPortalSleeper(),
      logoutBounder: shortBounder
    )
    let report = await workflow.run(
      credentials: try syntheticCredentials(),
      platformSerial: try syntheticSerial()
    )

    #expect(report.status == .logoutRejected)
    #expect(report.operations.logoutRequested)
    #expect(!report.operations.logoutAccepted)
    #expect(report.ownedMaterial.requestBodiesErased)
    #expect(report.ownedMaterial.responseBodiesErased)
    #expect(await transport.snapshots().count == 4)
    #expect(await transport.remainingStepCount() == 0)
  }

  @Test func detachedBounderHasAnExplicitDeadline() async {
    let bounder = TimedDetachedPortalLogoutBounder(timeoutNanoseconds: 1_000_000)
    let finished = await bounder.run {
      try? await Task.sleep(nanoseconds: UInt64.max)
    }
    #expect(!finished)
  }
}
