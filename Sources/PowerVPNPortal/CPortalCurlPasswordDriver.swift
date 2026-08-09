import CPortalCurl
import Foundation

struct CPortalCurlPasswordDriver: CurlPasswordDriving {
  init() throws {
    try Self.requireSuccess(pvcurl_runtime_preflight())
  }

  func perform(
    input: CurlPasswordTransferInput,
    body: UnsafeRawBufferPointer,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPasswordCancellation
  ) throws -> CurlPasswordTransferResult {
    try input.withCConfiguration(body: body, cookie: cookie) { configuration in
      var configuration = configuration
      var request: OpaquePointer?
      try Self.requireSuccess(pvcurl_password_request_create(&configuration, &request))
      guard let request else { throw PortalTransportError.unavailable }
      let reference = CPortalCurlRequestReference(request)
      cancellation.install { pvcurl_request_cancel(reference.pointer) }
      defer {
        cancellation.clear()
        pvcurl_request_destroy(reference.pointer)
      }

      var response = pvcurl_response_t()
      defer { pvcurl_response_destroy(&response) }
      try Self.requireSuccess(pvcurl_request_perform(reference.pointer, &response))
      return try Self.copyResponse(response, limits: input.limits)
    }
  }

  static func normalizedStatus(_ status: pvcurl_status_t) -> PortalTransportError? {
    switch status {
    case PVCURL_STATUS_OK: nil
    case PVCURL_STATUS_INVALID_ARGUMENT: .invalidRequest
    case PVCURL_STATUS_TRUST_REJECTED: .trustRejected
    case PVCURL_STATUS_REDIRECT_REJECTED: .redirectRejected
    case PVCURL_STATUS_AUTHENTICATION_REJECTED: .authenticationChallengeRejected
    case PVCURL_STATUS_HEADER_FRAMING_REJECTED: .invalidResponse
    case PVCURL_STATUS_RESPONSE_TOO_LARGE: .responseTooLarge
    case PVCURL_STATUS_CANCELLED: .cancelled
    case PVCURL_STATUS_TIMED_OUT: .timedOut
    default: .unavailable
    }
  }

  private static func requireSuccess(_ status: pvcurl_status_t) throws {
    if let error = normalizedStatus(status) { throw error }
  }

  private static func copyResponse(
    _ response: pvcurl_response_t,
    limits: CurlPasswordTransferLimits
  ) throws -> CurlPasswordTransferResult {
    guard response.effective_url_exact, (100...599).contains(Int(response.http_status)),
      !(300...399).contains(Int(response.http_status)),
      response.http_status != 401, response.http_status != 407,
      response.body_length <= limits.maximumResponseBodyBytes,
      (1...limits.maximumSetCookieBytes).contains(response.set_cookie_length),
      response.body_length == 0 || response.body != nil,
      response.set_cookie != nil
    else { throw PortalTransportError.invalidResponse }
    let body = try SecureBytes(
      copying: UnsafeRawBufferPointer(start: response.body, count: response.body_length)
    )
    do {
      let cookie = try SecureBytes(
        copying: UnsafeRawBufferPointer(
          start: response.set_cookie,
          count: response.set_cookie_length
        )
      )
      return CurlPasswordTransferResult(
        statusCode: Int(response.http_status),
        body: body,
        setCookie: cookie
      )
    } catch {
      body.erase()
      throw error
    }
  }
}

extension CurlPasswordTransferInput {
  fileprivate func withCConfiguration<Result>(
    body: UnsafeRawBufferPointer,
    cookie: UnsafeRawBufferPointer,
    _ operation: (pvcurl_password_request_config_t) throws -> Result
  ) rethrows -> Result {
    try url.withPVCurlBytes { url in
      try host.withPVCurlBytes { host in
        try accept.withPVCurlBytes { accept in
          try userAgent.withPVCurlBytes { userAgent in
            try contentType.withPVCurlBytes { contentType in
              try operation(
                pvcurl_password_request_config_t(
                  url: url,
                  host_header: host,
                  accept_header: accept,
                  user_agent_header: userAgent,
                  content_type_header: contentType,
                  cookie_header: cookie.pvcurlBytes,
                  body: body.pvcurlBytes,
                  timeout_milliseconds: limits.timeoutMilliseconds,
                  maximum_response_body_bytes: limits.maximumResponseBodyBytes,
                  maximum_response_header_bytes: limits.maximumResponseHeaderBytes,
                  maximum_response_header_line_bytes: limits.maximumResponseHeaderLineBytes,
                  maximum_set_cookie_bytes: limits.maximumSetCookieBytes
                )
              )
            }
          }
        }
      }
    }
  }
}

extension Array where Element == UInt8 {
  fileprivate func withPVCurlBytes<Result>(
    _ operation: (pvcurl_bytes_t) throws -> Result
  ) rethrows -> Result {
    try withUnsafeBufferPointer { buffer in
      try operation(pvcurl_bytes_t(pointer: buffer.baseAddress, length: buffer.count))
    }
  }
}

extension UnsafeRawBufferPointer {
  fileprivate var pvcurlBytes: pvcurl_bytes_t {
    let bytes = bindMemory(to: UInt8.self)
    return pvcurl_bytes_t(pointer: bytes.baseAddress, length: bytes.count)
  }
}

private final class CPortalCurlRequestReference: @unchecked Sendable {
  let pointer: OpaquePointer

  init(_ pointer: OpaquePointer) {
    self.pointer = pointer
  }
}

final class CurlPasswordCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?
  private var cancelled = false

  func install(_ handler: @escaping @Sendable () -> Void) {
    lock.withLock {
      if cancelled { handler() } else { self.handler = handler }
    }
  }

  func clear() {
    lock.withLock { handler = nil }
  }

  func cancel() {
    lock.withLock {
      cancelled = true
      handler?()
    }
  }
}

final class CurlPasswordCancellationRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var requests: [ObjectIdentifier: CurlPasswordCancellation] = [:]

  func register(_ request: CurlPasswordCancellation) {
    lock.withLock { requests[ObjectIdentifier(request)] = request }
  }

  func unregister(_ request: CurlPasswordCancellation) {
    _ = lock.withLock { requests.removeValue(forKey: ObjectIdentifier(request)) }
  }

  func cancelAll() {
    let active = lock.withLock {
      let active = Array(requests.values)
      requests.removeAll()
      return active
    }
    for request in active { request.cancel() }
  }
}
