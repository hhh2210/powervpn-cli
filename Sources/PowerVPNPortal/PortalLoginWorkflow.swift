import Foundation

struct PortalLoginWorkflow: Sendable {
  static let sessionCheckDelaySeconds: UInt64 = 60

  private let factory: PortalRequestFactory
  private let transport: any PortalTransporting
  private let sleeper: any PortalSleeping
  private let logoutBounder: any PortalLogoutBounding
  private let snapshotConsumer: any AuthenticatedPortalSnapshotConsuming
  private let authenticationFlow: PortalAuthenticationFlow

  init(
    factory: PortalRequestFactory,
    transport: any PortalTransporting,
    sleeper: any PortalSleeping = ContinuousPortalSleeper(),
    logoutBounder: any PortalLogoutBounding = TimedDetachedPortalLogoutBounder(),
    snapshotConsumer: any AuthenticatedPortalSnapshotConsuming =
      DiscardingAuthenticatedPortalSnapshotConsumer()
  ) throws {
    self.factory = factory
    self.transport = transport
    self.sleeper = sleeper
    self.logoutBounder = logoutBounder
    self.snapshotConsumer = snapshotConsumer
    authenticationFlow = try PortalAuthenticationFlow(
      factory: factory,
      transport: transport
    )
  }

  func run(
    credentials: PortalCredentials,
    platformSerial: SecureBytes
  ) async -> PortalLoginReport {
    var progress = PortalWorkflowProgress()
    var stage = PortalWorkflowStage.login
    var logoutAttempted = false
    var finalStatus = PortalLoginStatus.internalFailure
    let materialTracker = PortalOwnedMaterialTracker()
    var transportFailure: PortalTransportFailureEvidence?

    do {
      let snapshot = try await authenticationFlow.authenticateThroughResource(
        credentials: credentials,
        platformSerial: platformSerial,
        progress: &progress,
        tracker: materialTracker
      )

      stage = .authenticatedSnapshot
      do {
        try await consumeAuthenticatedSnapshot(snapshot)
      } catch is CancellationError {
        throw CancellationError()
      } catch {
        throw PortalWorkflowStop.status(.authenticatedSnapshotRejected)
      }

      stage = .delay
      try await sleeper.sleep(seconds: Self.sessionCheckDelaySeconds)

      stage = .session
      let sessionRequest = try factory.makeSessionCheckRequest()
      progress.sessionCheckRequested = true
      let sessionResponse = try await authenticationFlow.perform(
        sessionRequest,
        tracker: materialTracker
      )
      guard try sessionAccepted(sessionResponse, tracker: materialTracker) else {
        throw PortalWorkflowStop.status(.sessionRejected)
      }
      progress.sessionCheckAccepted = true

      stage = .logout
      logoutAttempted = true
      let logout = await boundedLogoutAttempt(tracker: materialTracker)
      progress.logoutRequested = logout.requested
      progress.logoutAccepted = logout.accepted
      if Task.isCancelled || logout.cancelled {
        throw PortalWorkflowStop.status(.cancelled)
      }
      guard logout.accepted else {
        throw PortalWorkflowStop.status(.logoutRejected)
      }
      finalStatus = .accepted
    } catch PortalWorkflowStop.status(let status) {
      finalStatus = status
    } catch {
      transportFailure = (error as? PortalTransportFailure)?.evidence
      finalStatus = PortalWorkflowErrorNormalizer.status(for: error, at: stage)
    }

    if progress.loginAccepted && !logoutAttempted {
      logoutAttempted = true
      let cleanup = await boundedLogoutAttempt(tracker: materialTracker)
      progress.logoutRequested = cleanup.requested
      progress.logoutAccepted = cleanup.accepted
    }

    credentials.erase()
    platformSerial.erase()
    factory.eraseSession()
    return makeReport(
      status: finalStatus,
      progress: progress,
      credentials: credentials,
      platformSerial: platformSerial,
      tracker: materialTracker,
      transportFailure: transportFailure
    )
  }

  func acquire(
    credentials: PortalCredentials,
    platformSerial: SecureBytes
  ) async -> PortalSnapshotAcquisitionResult {
    var progress = PortalWorkflowProgress()
    let tracker = PortalOwnedMaterialTracker()
    do {
      let snapshot = try await authenticationFlow.authenticateThroughResource(
        credentials: credentials,
        platformSerial: platformSerial,
        progress: &progress,
        tracker: tracker
      )
      credentials.erase()
      platformSerial.erase()
      let cleanup = tracker.snapshot
      guard !Task.isCancelled,
        credentials.usernameByteCount == 0,
        credentials.passwordByteCount == 0,
        platformSerial.count == 0,
        cleanup.requests,
        cleanup.responses,
        factory.retainedSessionByteCount > 0,
        snapshot.isAccessible
      else {
        snapshot.erase()
        let logout = await boundedLogoutAttempt(tracker: tracker)
        progress.logoutRequested = logout.requested
        progress.logoutAccepted = logout.accepted
        factory.eraseSession()
        return .rejected(
          makeReport(
            status: Task.isCancelled ? .cancelled : .internalFailure,
            progress: progress,
            credentials: credentials,
            platformSerial: platformSerial,
            tracker: tracker
          )
        )
      }
      return .acquired(
        AuthenticatedPortalLease(
          snapshot: snapshot,
          factory: factory,
          transport: transport,
          logoutBounder: logoutBounder
        )
      )
    } catch PortalWorkflowStop.status(let status) {
      credentials.erase()
      platformSerial.erase()
      if progress.loginAccepted {
        let logout = await boundedLogoutAttempt(tracker: tracker)
        progress.logoutRequested = logout.requested
        progress.logoutAccepted = logout.accepted
      }
      factory.eraseSession()
      return .rejected(
        makeReport(
          status: status,
          progress: progress,
          credentials: credentials,
          platformSerial: platformSerial,
          tracker: tracker
        )
      )
    } catch {
      credentials.erase()
      platformSerial.erase()
      if progress.loginAccepted {
        let logout = await boundedLogoutAttempt(tracker: tracker)
        progress.logoutRequested = logout.requested
        progress.logoutAccepted = logout.accepted
      }
      factory.eraseSession()
      let stage: PortalWorkflowStage = progress.loginAccepted ? .resource : .login
      return .rejected(
        makeReport(
          status: PortalWorkflowErrorNormalizer.status(for: error, at: stage),
          progress: progress,
          credentials: credentials,
          platformSerial: platformSerial,
          tracker: tracker,
          transportFailure: (error as? PortalTransportFailure)?.evidence
        )
      )
    }
  }

  private func makeReport(
    status: PortalLoginStatus,
    progress: PortalWorkflowProgress,
    credentials: PortalCredentials,
    platformSerial: SecureBytes,
    tracker: PortalOwnedMaterialTracker,
    transportFailure: PortalTransportFailureEvidence? = nil
  ) -> PortalLoginReport {
    let cleanup = tracker.snapshot
    return PortalLoginReport(
      status: status,
      operations: progress.evidence,
      ownedMaterial: PortalOwnedMaterialEvidence(
        credentialsErased: credentials.usernameByteCount == 0
          && credentials.passwordByteCount == 0
          && platformSerial.count == 0,
        requestBodiesErased: cleanup.requests,
        responseBodiesErased: cleanup.responses,
        sessionMaterialErased: factory.retainedSessionByteCount == 0
      ),
      transportFailure: transportFailure
    )
  }

  private func consumeAuthenticatedSnapshot(
    _ snapshot: AuthenticatedPortalSnapshot
  ) async throws {
    defer { snapshot.erase() }
    try await snapshotConsumer.consume(snapshot)
  }

  private func sessionAccepted(
    _ response: PortalHTTPResponse,
    tracker: PortalOwnedMaterialTracker
  ) throws -> Bool {
    defer {
      response.erase()
      tracker.observeErasedResponse(response)
    }
    guard response.statusCode == 200 else { return false }
    let document = try authenticationFlow.parse(response)
    defer { document.erase() }
    return try LeadSecPortalProfile.sessionDecision(document) == .accepted
  }

  private func boundedLogoutAttempt(
    tracker: PortalOwnedMaterialTracker
  ) async -> (requested: Bool, accepted: Bool, cancelled: Bool) {
    let observation = PortalLogoutObservation()
    let request: PortalHTTPRequest
    do {
      request = try factory.makeLogoutRequest()
    } catch {
      return observation.snapshot
    }
    observation.markRequested()
    let finished = await logoutBounder.run {
      await logoutAttempt(
        request: request,
        observation: observation,
        tracker: tracker
      )
    }
    if !finished {
      transport.cancel()
      request.erase()
      tracker.observeErasedRequest(request)
    }
    let snapshot = observation.snapshot
    return (snapshot.requested, snapshot.accepted, finished && snapshot.cancelled)
  }

  private func logoutAttempt(
    request: PortalHTTPRequest,
    observation: PortalLogoutObservation,
    tracker: PortalOwnedMaterialTracker
  ) async {
    guard !Task.isCancelled else {
      request.erase()
      return
    }
    do {
      let response = try await authenticationFlow.perform(request, tracker: tracker)
      response.erase()
      tracker.observeErasedResponse(response)
      if response.statusCode == 200 { observation.markAccepted() }
    } catch {
      if Task.isCancelled || error is CancellationError
        || (error as? PortalTransportError) == .cancelled
      {
        observation.markCancelled()
      }
    }
  }

}
