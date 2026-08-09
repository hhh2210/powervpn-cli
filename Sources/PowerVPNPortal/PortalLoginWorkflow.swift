import Foundation

private enum PortalWorkflowStage {
  case login, resource, delay, session, logout
}

private enum PortalWorkflowStop: Error {
  case status(PortalLoginStatus)
}

private enum PortalPasswordOutcome {
  case accepted
  case acceptedWithoutUsableSession
  case challengeRequired
  case rejected
}

struct PortalLoginWorkflow: Sendable {
  static let sessionCheckDelaySeconds: UInt64 = 60

  private let factory: PortalRequestFactory
  private let transport: any PortalTransporting
  private let sleeper: any PortalSleeping
  private let logoutBounder: any PortalLogoutBounding
  private let parser: PortalXMLStructuralParser

  init(
    factory: PortalRequestFactory,
    transport: any PortalTransporting,
    sleeper: any PortalSleeping = ContinuousPortalSleeper(),
    logoutBounder: any PortalLogoutBounding = TimedDetachedPortalLogoutBounder()
  ) throws {
    self.factory = factory
    self.transport = transport
    self.sleeper = sleeper
    self.logoutBounder = logoutBounder
    parser = try PortalXMLStructuralParser()
  }

  func run(
    credentials: PortalCredentials,
    platformSerial: SecureBytes
  ) async -> PortalLoginReport {
    var progress = PortalWorkflowProgress()
    var stage = PortalWorkflowStage.login
    var authenticated = false
    var logoutAttempted = false
    var finalStatus = PortalLoginStatus.internalFailure
    let materialTracker = PortalOwnedMaterialTracker()

    do {
      try Task.checkCancellation()
      let passwordRequest = try factory.makePasswordRequest(
        credentials: credentials,
        platformSerial: platformSerial
      )
      credentials.erase()
      platformSerial.erase()
      progress.loginRequested = true
      let passwordResponse = try await perform(passwordRequest, tracker: materialTracker)
      switch try passwordOutcome(
        passwordResponse,
        requestURL: passwordRequest.url,
        tracker: materialTracker
      ) {
      case .accepted:
        progress.loginAccepted = true
        authenticated = true
      case .acceptedWithoutUsableSession:
        progress.loginAccepted = true
        authenticated = true
        throw PortalWorkflowStop.status(.loginResponseRejected)
      case .challengeRequired:
        throw PortalWorkflowStop.status(.challengeRequired)
      case .rejected:
        throw PortalWorkflowStop.status(.loginRejected)
      }

      stage = .resource
      let resourceRequest = try factory.makeResourceRequest()
      progress.resourceListRequested = true
      let resourceResponse = try await perform(resourceRequest, tracker: materialTracker)
      guard try resourceAccepted(resourceResponse, tracker: materialTracker) else {
        throw PortalWorkflowStop.status(.resourceListRejected)
      }
      progress.resourceListAccepted = true

      stage = .delay
      try await sleeper.sleep(seconds: Self.sessionCheckDelaySeconds)

      stage = .session
      let sessionRequest = try factory.makeSessionCheckRequest()
      progress.sessionCheckRequested = true
      let sessionResponse = try await perform(sessionRequest, tracker: materialTracker)
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
      finalStatus = status(for: error, at: stage)
    }

    if authenticated && !logoutAttempted {
      logoutAttempted = true
      let cleanup = await boundedLogoutAttempt(tracker: materialTracker)
      progress.logoutRequested = cleanup.requested
      progress.logoutAccepted = cleanup.accepted
    }

    credentials.erase()
    platformSerial.erase()
    factory.eraseSession()
    let cleanup = materialTracker.snapshot
    return PortalLoginReport(
      status: finalStatus,
      operations: progress.evidence,
      ownedMaterial: PortalOwnedMaterialEvidence(
        credentialsErased: credentials.usernameByteCount == 0
          && credentials.passwordByteCount == 0
          && platformSerial.count == 0,
        requestBodiesErased: cleanup.requests,
        responseBodiesErased: cleanup.responses,
        sessionMaterialErased: factory.retainedSessionByteCount == 0
      )
    )
  }

  private func perform(
    _ request: PortalHTTPRequest,
    tracker: PortalOwnedMaterialTracker
  ) async throws -> PortalHTTPResponse {
    tracker.beginRequest(request)
    do {
      let response = try await transport.perform(request)
      request.erase()
      tracker.observeErasedRequest(request)
      tracker.beginResponse(response)
      return response
    } catch {
      request.erase()
      tracker.observeErasedRequest(request)
      throw error
    }
  }

  private func passwordOutcome(
    _ response: PortalHTTPResponse,
    requestURL: URL,
    tracker: PortalOwnedMaterialTracker
  ) throws -> PortalPasswordOutcome {
    defer {
      response.erase()
      tracker.observeErasedResponse(response)
    }
    guard response.statusCode == 200 else {
      throw PortalWorkflowStop.status(.loginResponseRejected)
    }
    let document = try parse(response)
    defer { document.erase() }
    switch try LeadSecPortalProfile.passwordDecision(document) {
    case .accepted:
      do {
        try factory.acceptPasswordSession(from: response, passwordURL: requestURL)
        return .accepted
      } catch {
        return .acceptedWithoutUsableSession
      }
    case .challengeRequired:
      return .challengeRequired
    case .rejected:
      return .rejected
    }
  }

  private func resourceAccepted(
    _ response: PortalHTTPResponse,
    tracker: PortalOwnedMaterialTracker
  ) throws -> Bool {
    defer {
      response.erase()
      tracker.observeErasedResponse(response)
    }
    guard response.statusCode == 200 else { return false }
    let document = try parse(response)
    defer { document.erase() }
    return try LeadSecPortalProfile.resourceAccepted(document)
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
    let document = try parse(response)
    defer { document.erase() }
    return try LeadSecPortalProfile.sessionDecision(document) == .accepted
  }

  private func parse(_ response: PortalHTTPResponse) throws -> PortalXMLDocument {
    let body = try response.withBodyBytes { try SecureBytes(copying: $0) }
    return try parser.parse(consuming: body)
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
      let response = try await perform(request, tracker: tracker)
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

  private func status(
    for error: Error,
    at stage: PortalWorkflowStage
  ) -> PortalLoginStatus {
    if Task.isCancelled || error is CancellationError { return .cancelled }
    if let transportError = error as? PortalTransportError {
      switch transportError {
      case .cancelled: return .cancelled
      case .trustRejected: return .tlsRejected
      case .redirectRejected, .originMismatch: return .redirectRejected
      default: break
      }
    }
    switch stage {
    case .login: return error is PortalTransportError ? .transportRejected : .loginResponseRejected
    case .resource: return .resourceListRejected
    case .delay: return .cancelled
    case .session: return .sessionRejected
    case .logout: return .logoutRejected
    }
  }
}
