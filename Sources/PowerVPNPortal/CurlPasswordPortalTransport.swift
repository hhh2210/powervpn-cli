import Foundation

struct CurlPasswordPortalTransport: PortalTransporting {
  static let defaultMaximumResponseBytes = 2 * 1_024 * 1_024
  static let maximumPermittedResponseBytes = 16 * 1_024 * 1_024
  static let defaultMaximumHeaderBytes = 64 * 1_024
  static let defaultMaximumHeaderLineBytes = 8 * 1_024
  static let defaultMaximumSetCookieBytes = 8 * 1_024
  static let defaultTimeout: TimeInterval = 15
  private static let maximumPasswordBodyBytes = 32 * 1_024

  private let allowedOrigin: PortalHTTPOrigin
  private let driver: any CurlPasswordDriving
  private let limits: CurlPasswordTransferLimits
  private let activeRequests = CurlPasswordCancellationRegistry()

  init(
    allowedOrigin: PortalHTTPOrigin,
    maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
    timeout: TimeInterval = Self.defaultTimeout
  ) throws {
    try self.init(
      allowedOrigin: allowedOrigin,
      driver: CPortalCurlPasswordDriver(),
      maximumResponseBytes: maximumResponseBytes,
      timeout: timeout
    )
  }

  init(
    allowedOrigin: PortalHTTPOrigin,
    driver: any CurlPasswordDriving,
    maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
    timeout: TimeInterval = Self.defaultTimeout
  ) throws {
    guard (1...Self.maximumPermittedResponseBytes).contains(maximumResponseBytes),
      timeout.isFinite, timeout > 0, timeout <= 60
    else { throw PortalTransportError.invalidRequest }
    self.allowedOrigin = allowedOrigin
    self.driver = driver
    limits = CurlPasswordTransferLimits(
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
    guard let body = request.requestBody, let cookie = request.cookieHeader else {
      throw PortalTransportError.invalidRequest
    }
    let input = CurlPasswordTransferInput(
      url: Array(request.url.absoluteString.utf8),
      host: Array(allowedOrigin.authority.utf8),
      accept: Array(request.headers.accept.utf8),
      userAgent: Array(request.headers.userAgent.utf8),
      contentType: Array(PortalWireContract.passwordContentType.utf8),
      limits: limits
    )
    let cancellation = CurlPasswordCancellation()
    activeRequests.register(cancellation)
    defer { activeRequests.unregister(cancellation) }

    do {
      let operation = Task.detached { [driver] in
        try body.withUnsafeBytes { bodyBytes in
          try cookie.withUnsafeBytes { cookieBytes in
            try driver.perform(
              input: input,
              body: bodyBytes,
              cookie: cookieBytes,
              cancellation: cancellation
            )
          }
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
        setCookieProjection: .provenSingleWireHeader
      )
    } catch {
      throw normalize(error)
    }
  }

  func cancel() {
    activeRequests.cancelAll()
  }

  private func validate(_ request: PortalHTTPRequest) throws {
    guard request.hasOperationProof(.password),
      request.method == .post, allowedOrigin.matches(request.url),
      request.url.user == nil, request.url.password == nil,
      request.url.query == nil, request.url.fragment == nil,
      request.headers.accept == PortalWireContract.accept,
      request.headers.contentType == PortalWireContract.passwordContentType,
      let components = URLComponents(url: request.url, resolvingAgainstBaseURL: false),
      components.percentEncodedPath == PortalWireContract.passwordPath,
      let body = request.requestBody, let cookie = request.cookieHeader,
      (1...Self.maximumPasswordBodyBytes).contains(body.count)
    else { throw PortalTransportError.invalidRequest }
    try cookie.withUnsafeBytes { bytes in
      guard (1...Self.defaultMaximumSetCookieBytes).contains(bytes.count),
        bytes.allSatisfy({ (0x20...0x7e).contains($0) })
      else { throw PortalTransportError.invalidRequest }
    }
  }

  private func normalize(_ error: Error) -> PortalTransportError {
    if Task.isCancelled || error is CancellationError { return .cancelled }
    return (error as? PortalTransportError) ?? .unavailable
  }
}

struct CurlPasswordTransferLimits: Sendable {
  let timeoutMilliseconds: UInt32
  let maximumResponseBodyBytes: Int
  let maximumResponseHeaderBytes: Int
  let maximumResponseHeaderLineBytes: Int
  let maximumSetCookieBytes: Int
}

struct CurlPasswordTransferInput: Sendable {
  let url: [UInt8]
  let host: [UInt8]
  let accept: [UInt8]
  let userAgent: [UInt8]
  let contentType: [UInt8]
  let limits: CurlPasswordTransferLimits
}

struct CurlPasswordTransferResult: Sendable {
  let statusCode: Int
  let body: SecureBytes
  let setCookie: SecureBytes

  func erase() {
    body.erase()
    setCookie.erase()
  }
}

protocol CurlPasswordDriving: Sendable {
  func perform(
    input: CurlPasswordTransferInput,
    body: UnsafeRawBufferPointer,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPasswordCancellation
  ) throws -> CurlPasswordTransferResult
}
