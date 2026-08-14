import Foundation

struct CurlPortalTransport: PortalTransporting {
  static let defaultMaximumResponseBytes = 2 * 1_024 * 1_024
  static let maximumPermittedResponseBytes = 16 * 1_024 * 1_024
  static let defaultMaximumHeaderBytes = 64 * 1_024
  static let defaultMaximumHeaderLineBytes = 8 * 1_024
  static let defaultMaximumSetCookieBytes = 8 * 1_024
  static let defaultTimeout: TimeInterval = 15
  private static let maximumPasswordBodyBytes = 32 * 1_024

  private let allowedOrigin: PortalHTTPOrigin
  private let driver: any CurlPortalDriving
  private let limits: CurlPortalTransferLimits
  private let activeRequests = CurlPortalCancellationRegistry()

  init(
    allowedOrigin: PortalHTTPOrigin,
    maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
    timeout: TimeInterval = Self.defaultTimeout
  ) throws {
    try self.init(
      allowedOrigin: allowedOrigin,
      driver: CPortalCurlDriver(),
      maximumResponseBytes: maximumResponseBytes,
      timeout: timeout
    )
  }

  init(
    allowedOrigin: PortalHTTPOrigin,
    driver: any CurlPortalDriving,
    maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
    timeout: TimeInterval = Self.defaultTimeout
  ) throws {
    guard (1...Self.maximumPermittedResponseBytes).contains(maximumResponseBytes),
      timeout.isFinite, timeout > 0, timeout <= 60
    else { throw PortalTransportError.invalidRequest }
    self.allowedOrigin = allowedOrigin
    self.driver = driver
    limits = CurlPortalTransferLimits(
      timeoutMilliseconds: UInt32((timeout * 1_000).rounded(.up)),
      maximumResponseBodyBytes: maximumResponseBytes,
      maximumResponseHeaderBytes: Self.defaultMaximumHeaderBytes,
      maximumResponseHeaderLineBytes: Self.defaultMaximumHeaderLineBytes,
      maximumSetCookieBytes: Self.defaultMaximumSetCookieBytes
    )
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    guard request.begin() else { throw PortalTransportError.invalidRequest }
    defer { request.erase() }
    try validate(request)
    guard let cookie = request.cookieHeader else { throw PortalTransportError.invalidRequest }
    let input = CurlPortalTransferInput(
      method: request.method,
      requireSetCookie: false,
      url: Array(request.url.absoluteString.utf8),
      host: Array(allowedOrigin.authority.utf8),
      accept: Array(request.headers.accept.utf8),
      userAgent: Array(request.headers.userAgent.utf8),
      contentType: request.headers.contentType.map { Array($0.utf8) },
      limits: limits
    )
    let cancellation = CurlPortalCancellation()
    activeRequests.register(cancellation)
    defer { activeRequests.unregister(cancellation) }

    do {
      let operation = Task.detached { [driver] in
        try cookie.withUnsafeBytes { cookieBytes in
          if let body = request.requestBody {
            return try body.withUnsafeBytes { bodyBytes in
              try driver.perform(
                input: input,
                body: bodyBytes,
                cookie: cookieBytes,
                cancellation: cancellation
              )
            }
          }
          return try driver.perform(
            input: input,
            body: nil,
            cookie: cookieBytes,
            cancellation: cancellation
          )
        }
      }
      let result = try await withTaskCancellationHandler {
        try await operation.value
      } onCancel: {
        cancellation.cancel()
      }
      guard !Task.isCancelled else {
        result.erase()
        throw PortalTransportError.cancelled
      }
      return PortalHTTPResponse(
        statusCode: result.statusCode,
        body: result.body,
        setCookieHeader: result.setCookie,
        setCookieProjection: result.setCookieProjection
      )
    } catch {
      throw normalize(error)
    }
  }

  func cancel() {
    activeRequests.cancelAll()
  }

  @discardableResult
  private func validate(_ request: PortalHTTPRequest) throws -> PortalRequestOperation {
    guard allowedOrigin.matches(request.url), request.url.user == nil,
      request.url.password == nil, request.url.fragment == nil,
      request.headers.accept == PortalWireContract.accept,
      let cookie = request.cookieHeader,
      let components = URLComponents(url: request.url, resolvingAgainstBaseURL: false)
    else { throw PortalTransportError.invalidRequest }
    try cookie.withUnsafeBytes { bytes in
      guard (1...Self.defaultMaximumSetCookieBytes).contains(bytes.count),
        bytes.allSatisfy({ (0x20...0x7e).contains($0) })
      else { throw PortalTransportError.invalidRequest }
    }
    let path = components.percentEncodedPath
    let query = components.percentEncodedQuery
    switch (request.method, path, query) {
    case (.post, PortalWireContract.passwordPath, nil)
    where request.hasOperationProof(.password)
      && request.headers.contentType == PortalWireContract.passwordContentType
      && request.requestBody.map({ (1...Self.maximumPasswordBodyBytes).contains($0.count) }) == true:
      return .password
    case (.get, PortalWireContract.resourcePath, "version=2.0")
    where request.hasOperationProof(.resource)
      && request.headers.contentType == nil && request.requestBody == nil:
      return .resource
    case (.get, PortalWireContract.sessionCheckPath, "key=hostid")
    where request.hasOperationProof(.session)
      && request.headers.contentType == nil && request.requestBody == nil:
      return .session
    case (.post, PortalWireContract.logoutPath, nil)
    where request.hasOperationProof(.logout)
      && request.headers.contentType == nil && request.requestBody == nil:
      return .logout
    default:
      throw PortalTransportError.invalidRequest
    }
  }

  private func normalize(_ error: Error) -> any Error {
    if let failure = error as? PortalTransportFailure { return failure }
    if Task.isCancelled || error is CancellationError { return PortalTransportError.cancelled }
    return (error as? PortalTransportError) ?? .unavailable
  }
}

struct CurlPortalTransferLimits: Sendable {
  let timeoutMilliseconds: UInt32
  let maximumResponseBodyBytes: Int
  let maximumResponseHeaderBytes: Int
  let maximumResponseHeaderLineBytes: Int
  let maximumSetCookieBytes: Int
}

struct CurlPortalTransferInput: Sendable {
  let method: PortalHTTPMethod
  let requireSetCookie: Bool
  let url: [UInt8]
  let host: [UInt8]
  let accept: [UInt8]
  let userAgent: [UInt8]
  let contentType: [UInt8]?
  let limits: CurlPortalTransferLimits
}

struct CurlPortalTransferResult: Sendable {
  let statusCode: Int
  let body: SecureBytes
  let setCookie: SecureBytes?
  let setCookieProjection: LeadSecSetCookieProjection

  func erase() {
    body.erase()
    setCookie?.erase()
  }
}

protocol CurlPortalDriving: Sendable {
  func perform(
    input: CurlPortalTransferInput,
    body: UnsafeRawBufferPointer?,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPortalCancellation
  ) throws -> CurlPortalTransferResult
}
