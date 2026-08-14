import Foundation

/// Enforces the exact four-operation Portal dialect before handing every
/// request to the same connection-bound pinned transport.
struct LeadSecPortalTransport: PortalTransporting {
  private let allowedOrigin: PortalHTTPOrigin
  private let transport: any PortalTransporting

  init(
    allowedOrigin: PortalHTTPOrigin,
    transport: any PortalTransporting
  ) {
    self.allowedOrigin = allowedOrigin
    self.transport = transport
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    guard allows(request) else {
      guard request.begin() else { throw PortalTransportError.invalidRequest }
      request.erase()
      throw PortalTransportError.invalidRequest
    }
    return try await transport.perform(request)
  }

  func cancel() {
    transport.cancel()
  }

  private func allows(_ request: PortalHTTPRequest) -> Bool {
    guard allowedOrigin.matches(request.url),
      request.url.user == nil, request.url.password == nil,
      request.url.fragment == nil,
      request.headers.accept == PortalWireContract.accept,
      request.cookieHeader != nil,
      let components = URLComponents(
        url: request.url,
        resolvingAgainstBaseURL: false
      )
    else { return false }

    let path = components.percentEncodedPath
    let query = components.percentEncodedQuery
    switch (request.method, path, query) {
    case (.post, PortalWireContract.passwordPath, nil):
      return request.hasOperationProof(.password)
        && request.requestBody != nil
        && request.headers.contentType == PortalWireContract.passwordContentType
    case (.get, PortalWireContract.resourcePath, "version=2.0"):
      return request.hasOperationProof(.resource)
        && request.requestBody == nil && request.headers.contentType == nil
    case (.get, PortalWireContract.sessionCheckPath, "key=hostid"):
      return request.hasOperationProof(.session)
        && request.requestBody == nil && request.headers.contentType == nil
    case (.post, PortalWireContract.logoutPath, nil):
      return request.hasOperationProof(.logout)
        && request.requestBody == nil && request.headers.contentType == nil
    default:
      return false
    }
  }
}
