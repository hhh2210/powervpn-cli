import Foundation

/// Keeps the raw-header compatibility exception scoped to the exact password
/// request. Every other request continues through the upstream-style
/// Foundation transport.
struct LeadSecPortalTransport: PortalTransporting {
  private let allowedOrigin: PortalHTTPOrigin
  private let passwordTransport: any PortalTransporting
  private let sessionTransport: any PortalTransporting

  init(
    allowedOrigin: PortalHTTPOrigin,
    passwordTransport: any PortalTransporting,
    sessionTransport: any PortalTransporting
  ) {
    self.allowedOrigin = allowedOrigin
    self.passwordTransport = passwordTransport
    self.sessionTransport = sessionTransport
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    switch route(request) {
    case .password:
      return try await passwordTransport.perform(request)
    case .session:
      return try await sessionTransport.perform(request)
    case .reject:
      guard request.begin() else { throw PortalTransportError.invalidRequest }
      request.erase()
      throw PortalTransportError.invalidRequest
    }
  }

  func cancel() {
    passwordTransport.cancel()
    sessionTransport.cancel()
  }

  private func route(_ request: PortalHTTPRequest) -> Route {
    guard allowedOrigin.matches(request.url),
      request.url.user == nil, request.url.password == nil,
      request.url.fragment == nil,
      request.headers.accept == PortalWireContract.accept,
      request.cookieHeader != nil,
      let components = URLComponents(
        url: request.url,
        resolvingAgainstBaseURL: false
      )
    else { return .reject }

    let path = components.percentEncodedPath
    let query = components.percentEncodedQuery
    switch (request.method, path, query) {
    case (.post, PortalWireContract.passwordPath, nil)
    where request.hasOperationProof(.password)
      && request.requestBody != nil
      && request.headers.contentType == PortalWireContract.passwordContentType:
      return .password
    case (.get, PortalWireContract.resourcePath, "version=2.0")
    where request.hasOperationProof(.resource)
      && request.requestBody == nil && request.headers.contentType == nil:
      return .session
    case (.get, PortalWireContract.sessionCheckPath, "key=hostid")
    where request.hasOperationProof(.session)
      && request.requestBody == nil && request.headers.contentType == nil:
      return .session
    case (.post, PortalWireContract.logoutPath, nil)
    where request.hasOperationProof(.logout)
      && request.requestBody == nil && request.headers.contentType == nil:
      return .session
    default:
      return .reject
    }
  }
}

private enum Route {
  case password, session, reject
}
