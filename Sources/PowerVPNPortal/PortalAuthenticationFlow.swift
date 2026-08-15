import Foundation

enum PortalWorkflowStage {
  case login, resource, authenticatedSnapshot, delay, session, logout
}

enum PortalWorkflowStop: Error {
  case status(PortalLoginStatus)
}

private enum PortalPasswordOutcome {
  case accepted
  case challengeRequired
  case rejected
}

struct PortalAuthenticationFlow: Sendable {
  let factory: PortalRequestFactory
  let transport: any PortalTransporting
  private let parser: PortalXMLStructuralParser

  init(
    factory: PortalRequestFactory,
    transport: any PortalTransporting
  ) throws {
    self.factory = factory
    self.transport = transport
    parser = try PortalXMLStructuralParser()
  }

  func authenticateThroughResource(
    credentials: PortalCredentials,
    platformSerial: SecureBytes,
    progress: inout PortalWorkflowProgress,
    tracker: PortalOwnedMaterialTracker
  ) async throws -> AuthenticatedPortalSnapshot {
    do {
      try Task.checkCancellation()
      let passwordRequest = try factory.makePasswordRequest(
        credentials: credentials,
        platformSerial: platformSerial
      )
      credentials.erase()
      platformSerial.erase()
      progress.loginRequested = true
      let passwordResponse = try await perform(passwordRequest, tracker: tracker)
      switch try passwordOutcome(
        passwordResponse,
        requestURL: passwordRequest.url,
        tracker: tracker
      ) {
      case .accepted:
        progress.loginAccepted = true
      case .challengeRequired:
        throw PortalWorkflowStop.status(.challengeRequired)
      case .rejected:
        throw PortalWorkflowStop.status(.loginRejected)
      }
    } catch let stop as PortalWorkflowStop {
      throw stop
    } catch let failure as PortalTransportFailure {
      throw failure
    } catch {
      throw PortalWorkflowStop.status(
        PortalWorkflowErrorNormalizer.status(for: error, at: .login)
      )
    }

    do {
      let resourceRequest = try factory.makeResourceRequest()
      progress.resourceListRequested = true
      let resourceResponse = try await perform(resourceRequest, tracker: tracker)
      guard
        let snapshot = try authenticatedSnapshot(
          resourceResponse,
          request: resourceRequest,
          tracker: tracker
        )
      else {
        throw PortalWorkflowStop.status(.resourceListRejected)
      }
      progress.resourceListAccepted = true
      return snapshot
    } catch let stop as PortalWorkflowStop {
      throw stop
    } catch let failure as PortalTransportFailure {
      throw failure
    } catch {
      throw PortalWorkflowStop.status(
        PortalWorkflowErrorNormalizer.status(for: error, at: .resource)
      )
    }
  }

  func perform(
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

  func parse(_ response: PortalHTTPResponse) throws -> PortalXMLDocument {
    let body = try response.withBodyBytes { try SecureBytes(copying: $0) }
    return try parser.parse(consuming: body)
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
    guard (200...204).contains(response.statusCode) else {
      throw PortalWorkflowStop.status(.loginResponseRejected)
    }
    let document = try parse(response)
    defer { document.erase() }
    switch try LeadSecPortalProfile.passwordDecision(document) {
    case .accepted:
      try factory.acceptPasswordSession(from: response, passwordURL: requestURL)
      return .accepted
    case .challengeRequired:
      return .challengeRequired
    case .rejected:
      return .rejected
    }
  }

  private func authenticatedSnapshot(
    _ response: PortalHTTPResponse,
    request: PortalHTTPRequest,
    tracker: PortalOwnedMaterialTracker
  ) throws -> AuthenticatedPortalSnapshot? {
    defer {
      response.erase()
      tracker.observeErasedResponse(response)
    }
    guard response.statusCode == 200 else { return nil }
    let document = try parse(response)
    do {
      guard try LeadSecPortalProfile.resourceAccepted(document) else {
        document.erase()
        return nil
      }
      return try factory.mintAuthenticatedSnapshot(
        resourceRequest: request,
        resourceDocument: document
      )
    } catch {
      document.erase()
      throw error
    }
  }
}

enum PortalWorkflowErrorNormalizer {
  static func status(
    for error: Error,
    at stage: PortalWorkflowStage
  ) -> PortalLoginStatus {
    if Task.isCancelled || error is CancellationError { return .cancelled }
    let transportError =
      (error as? PortalTransportFailure)?.transportError
      ?? (error as? PortalTransportError)
    if let transportError {
      switch transportError {
      case .cancelled: return .cancelled
      case .trustRejected: return .tlsRejected
      case .redirectRejected, .originMismatch: return .redirectRejected
      default: break
      }
    }
    switch stage {
    case .login: return transportError == nil ? .loginResponseRejected : .transportRejected
    case .resource: return .resourceListRejected
    case .authenticatedSnapshot: return .authenticatedSnapshotRejected
    case .delay: return .cancelled
    case .session: return .sessionRejected
    case .logout: return .logoutRejected
    }
  }
}
