import Foundation

struct URLSessionPortalTransport: PortalTransporting {
  static let defaultMaximumResponseBytes = 2 * 1_024 * 1_024
  static let maximumPermittedResponseBytes = 16 * 1_024 * 1_024
  static let defaultTimeout: TimeInterval = 15

  private let allowedOrigin: PortalHTTPOrigin
  private let session: any PortalURLSessionPerforming
  private let maximumResponseBytes: Int
  private let timeout: TimeInterval
  private let activeRequests = PortalRequestCancellationRegistry()

  init(
    allowedOrigin: PortalHTTPOrigin,
    delegate: PortalURLSessionDelegate,
    maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
    timeout: TimeInterval = Self.defaultTimeout
  ) throws {
    try Self.validateLimits(maximumResponseBytes, timeout: timeout)
    let configuration = Self.makeEphemeralConfiguration(timeout: timeout)
    let urlSession = URLSession(
      configuration: configuration,
      delegate: delegate,
      delegateQueue: nil
    )
    self.init(
      allowedOrigin: allowedOrigin,
      session: FoundationPortalURLSession(session: urlSession),
      maximumResponseBytes: maximumResponseBytes,
      timeout: timeout
    )
  }

  init(
    allowedOrigin: PortalHTTPOrigin,
    session: any PortalURLSessionPerforming,
    maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
    timeout: TimeInterval = Self.defaultTimeout
  ) {
    self.allowedOrigin = allowedOrigin
    self.session = session
    self.maximumResponseBytes = maximumResponseBytes
    self.timeout = timeout
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    guard request.begin() else { throw PortalTransportError.invalidRequest }
    defer { request.erase() }
    try validate(request)
    let urlRequest = try makeURLRequest(request)
    let cancellation = PortalRequestCancellation()
    activeRequests.register(cancellation)
    defer { activeRequests.unregister(cancellation) }

    do {
      return try await withTaskCancellationHandler {
        let operation = Task { [session, allowedOrigin, maximumResponseBytes] in
          let stream = try await session.open(urlRequest)
          return try await Self.consume(
            stream,
            requestURL: request.url,
            allowedOrigin: allowedOrigin,
            maximumResponseBytes: maximumResponseBytes
          )
        }
        cancellation.install(operation)
        return try await operation.value
      } onCancel: {
        activeRequests.cancel(cancellation)
      }
    } catch {
      throw normalize(error)
    }
  }

  func cancel() {
    activeRequests.cancelAll()
  }

  static func makeEphemeralConfiguration(
    timeout: TimeInterval = defaultTimeout
  ) -> URLSessionConfiguration {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.urlCredentialStorage = nil
    configuration.waitsForConnectivity = false
    configuration.timeoutIntervalForRequest = timeout
    configuration.timeoutIntervalForResource = timeout
    configuration.httpMaximumConnectionsPerHost = 1
    return configuration
  }

  private static func validateLimits(_ maximumBytes: Int, timeout: TimeInterval) throws {
    guard (1...maximumPermittedResponseBytes).contains(maximumBytes),
      timeout.isFinite, timeout > 0, timeout <= 60
    else { throw PortalTransportError.invalidRequest }
  }

  private func validate(_ request: PortalHTTPRequest) throws {
    guard request.url.scheme?.lowercased() == "https" else {
      throw PortalTransportError.insecureTransport
    }
    guard request.url.fragment == nil, request.url.user == nil, request.url.password == nil else {
      throw PortalTransportError.invalidRequest
    }
    guard allowedOrigin.matches(request.url) else { throw PortalTransportError.originMismatch }
    if request.method == .post, request.url.path == PortalWireContract.passwordPath,
      session.passwordSetCookieProjection != .provenSingleWireHeader
    {
      throw PortalTransportError.setCookieFramingUnavailable
    }
    if request.method == .get, request.requestBody != nil {
      throw PortalTransportError.invalidRequest
    }
  }

  private func makeURLRequest(_ request: PortalHTTPRequest) throws -> URLRequest {
    var result = URLRequest(
      url: request.url,
      cachePolicy: .reloadIgnoringLocalCacheData,
      timeoutInterval: timeout
    )
    result.httpMethod = request.method.rawValue
    result.httpShouldHandleCookies = false
    result.setValue(allowedOrigin.authority, forHTTPHeaderField: "Host")
    result.setValue(request.headers.accept, forHTTPHeaderField: "Accept")
    result.setValue(request.headers.userAgent, forHTTPHeaderField: "User-Agent")
    if let contentType = request.headers.contentType {
      result.setValue(contentType, forHTTPHeaderField: "Content-Type")
    }
    if let body = request.requestBody {
      result.setValue(String(body.count), forHTTPHeaderField: "Content-Length")
      result.httpBodyStream = SecureBodyInputStream(bytes: body)
    }
    if let cookie = request.cookieHeader {
      try cookie.withUnsafeBytes { bytes in
        guard (1...8_192).contains(bytes.count),
          bytes.allSatisfy({ (0x20...0x7e).contains($0) })
        else { throw PortalTransportError.invalidRequest }
        let transient = String(decoding: bytes, as: UTF8.self)
        result.setValue(transient, forHTTPHeaderField: "Cookie")
      }
    }
    return result
  }

  private static func consume(
    _ stream: PortalSessionByteStream,
    requestURL: URL,
    allowedOrigin: PortalHTTPOrigin,
    maximumResponseBytes: Int
  ) async throws -> PortalHTTPResponse {
    var transferredCookie = false
    defer {
      if !transferredCookie { stream.head.setCookieHeader?.erase() }
    }
    guard (100...599).contains(stream.head.statusCode) else {
      stream.cancel()
      throw PortalTransportError.invalidResponse
    }
    guard allowedOrigin.matches(stream.head.finalURL) else {
      stream.cancel()
      throw PortalTransportError.originMismatch
    }
    guard stream.head.finalURL.absoluteString == requestURL.absoluteString,
      !(300...399).contains(stream.head.statusCode)
    else {
      stream.cancel()
      throw PortalTransportError.redirectRejected
    }
    guard stream.head.statusCode != 401, stream.head.statusCode != 407 else {
      stream.cancel()
      throw PortalTransportError.authenticationChallengeRejected
    }

    let accumulator = try SecureResponseAccumulator(capacity: maximumResponseBytes)
    do {
      for try await byte in stream.bytes {
        try Task.checkCancellation()
        guard accumulator.append(byte) else {
          throw PortalTransportError.responseTooLarge
        }
      }
      try Task.checkCancellation()
      let response = PortalHTTPResponse(
        statusCode: stream.head.statusCode,
        body: try accumulator.finish(),
        setCookieHeader: stream.head.setCookieHeader,
        setCookieProjection: stream.head.setCookieProjection
      )
      transferredCookie = true
      return response
    } catch {
      stream.cancel()
      throw error
    }
  }

  private func normalize(_ error: Error) -> PortalTransportError {
    if Task.isCancelled || error is CancellationError { return .cancelled }
    if let error = error as? PortalTransportError { return error }
    guard let urlError = error as? URLError else { return .unavailable }
    switch urlError.code {
    case .cancelled: return .cancelled
    case .timedOut: return .timedOut
    case .userAuthenticationRequired, .clientCertificateRejected, .clientCertificateRequired:
      return .authenticationChallengeRejected
    case .serverCertificateHasBadDate, .serverCertificateUntrusted,
      .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .secureConnectionFailed:
      return .trustRejected
    default: return .unavailable
    }
  }
}

final class FoundationPortalURLSession: @unchecked Sendable, PortalURLSessionPerforming {
  private let session: URLSession
  let passwordSetCookieProjection = LeadSecSetCookieProjection.foundationFoldedValue

  init(session: URLSession) {
    self.session = session
  }

  func open(_ request: URLRequest) async throws -> PortalSessionByteStream {
    let (source, response) = try await session.bytes(for: request)
    guard let response = response as? HTTPURLResponse, let finalURL = response.url else {
      throw PortalTransportError.invalidResponse
    }
    let setCookie = try Self.copySetCookie(response)
    let cancellation = PortalStreamCancellation()
    let stream = AsyncThrowingStream<UInt8, Error> { continuation in
      let task = Task {
        do {
          for try await byte in source { continuation.yield(byte) }
          continuation.finish()
        } catch {
          continuation.finish(throwing: error)
        }
      }
      cancellation.install(task)
      continuation.onTermination = { _ in cancellation.cancel() }
    }
    return PortalSessionByteStream(
      head: PortalSessionResponseHead(
        statusCode: response.statusCode,
        finalURL: finalURL,
        setCookieHeader: setCookie,
        setCookieProjection: setCookie == nil ? .unavailableOrAmbiguous : .foundationFoldedValue
      ),
      bytes: stream,
      cancel: { cancellation.cancel() }
    )
  }

  deinit {
    session.invalidateAndCancel()
  }

  static func copySetCookie(_ response: HTTPURLResponse) throws -> SecureBytes? {
    guard let value = response.value(forHTTPHeaderField: "Set-Cookie") else { return nil }
    let bytes = value.utf8
    guard (1...8_192).contains(bytes.count),
      bytes.allSatisfy({ (0x20...0x7e).contains($0) })
    else { throw PortalTransportError.invalidResponse }
    var iterator = bytes.makeIterator()
    return try SecureBytes.allocate(count: bytes.count) { output in
      for index in output.indices {
        guard let byte = iterator.next() else { throw PortalTransportError.invalidResponse }
        output[index] = byte
      }
    }
  }
}

private final class PortalStreamCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<Void, Never>?
  private var cancelled = false

  func install(_ task: Task<Void, Never>) {
    lock.withLock {
      if cancelled { task.cancel() } else { self.task = task }
    }
  }

  func cancel() {
    lock.withLock {
      cancelled = true
      task?.cancel()
      task = nil
    }
  }
}
