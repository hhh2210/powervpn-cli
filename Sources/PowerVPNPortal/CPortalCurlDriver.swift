import CPortalCurl
import Foundation

struct PortalTransportFailure: Error, Equatable, Sendable, CustomStringConvertible {
  let transportError: PortalTransportError
  let evidence: PortalTransportFailureEvidence

  var description: String { transportError.description }
}

struct CPortalCurlDriver: CurlPortalDriving {
  init() throws {
    try Self.requireSuccess(pvcurl_runtime_preflight())
  }

  func perform(
    input: CurlPortalTransferInput,
    body: UnsafeRawBufferPointer?,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPortalCancellation
  ) throws -> CurlPortalTransferResult {
    try input.withCConfiguration(body: body, cookie: cookie) { configuration in
      var configuration = configuration
      var request: OpaquePointer?
      try Self.requireSuccess(pvcurl_request_create(&configuration, &request))
      guard let request else { throw PortalTransportError.unavailable }
      let reference = CPortalCurlRequestReference(request)
      cancellation.install { pvcurl_request_cancel(reference.pointer) }
      defer {
        cancellation.clear()
        pvcurl_request_destroy(reference.pointer)
      }

      var response = pvcurl_response_t()
      defer { pvcurl_response_destroy(&response) }
      let status = pvcurl_request_perform(reference.pointer, &response)
      var diagnostics = pvcurl_transfer_diagnostics_t()
      let diagnosticsStatus = pvcurl_request_get_diagnostics(reference.pointer, &diagnostics)
      try Self.requireSuccess(
        status,
        diagnostics: diagnosticsStatus == PVCURL_STATUS_OK && diagnostics.status == status
          ? diagnostics : nil
      )
      return try Self.copyResponse(
        response,
        requireSetCookie: input.requireSetCookie,
        limits: input.limits
      )
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
  static func normalizedFailure(
    _ status: pvcurl_status_t,
    diagnostics: pvcurl_transfer_diagnostics_t? = nil
  ) -> PortalTransportFailure? {
    guard let transportError = normalizedStatus(status),
      let category = failureCategory(status)
    else { return nil }
    let headersObserved = diagnostics?.response_headers_observed == true
    return PortalTransportFailure(
      transportError: transportError,
      evidence: PortalTransportFailureEvidence(
        category: category,
        setCookieFieldCount: headersObserved ? diagnostics?.set_cookie_field_count : nil,
        setCookieWireSelection: headersObserved
          ? wireSelection(diagnostics?.set_cookie_selection) : nil,
        duplicateSetCookieRejected: headersObserved
          ? diagnostics?.duplicate_set_cookie_rejected : nil
      )
    )
  }

  private static func failureCategory(
    _ status: pvcurl_status_t
  ) -> PortalTransportFailureCategory? {
    switch status {
    case PVCURL_STATUS_OK: nil
    case PVCURL_STATUS_INVALID_ARGUMENT: .invalidRequest
    case PVCURL_STATUS_SETUP_FAILED: .setupFailed
    case PVCURL_STATUS_TRUST_REJECTED: .trustRejected
    case PVCURL_STATUS_REDIRECT_REJECTED: .redirectRejected
    case PVCURL_STATUS_AUTHENTICATION_REJECTED: .httpAuthenticationRejected
    case PVCURL_STATUS_HEADER_FRAMING_REJECTED: .headerFramingRejected
    case PVCURL_STATUS_RESPONSE_TOO_LARGE: .responseTooLarge
    case PVCURL_STATUS_CANCELLED: .cancelled
    case PVCURL_STATUS_TIMED_OUT: .timedOut
    case PVCURL_STATUS_UNAVAILABLE: .unavailable
    default: .unavailable
    }
  }

  private static func wireSelection(
    _ selection: pvcurl_set_cookie_selection_t?
  ) -> PortalSetCookieWireSelection? {
    selection == PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS ? .lastFieldWins : nil
  }

  private static func requireSuccess(
    _ status: pvcurl_status_t,
    diagnostics: pvcurl_transfer_diagnostics_t? = nil
  ) throws {
    if let failure = normalizedFailure(status, diagnostics: diagnostics) {
      throw failure
    }
  }

  static func copyResponse(
    _ response: pvcurl_response_t,
    requireSetCookie: Bool,
    limits: CurlPortalTransferLimits
  ) throws -> CurlPortalTransferResult {
    let cookieAbsent = response.set_cookie == nil && response.set_cookie_length == 0
    let cookiePresent =
      response.set_cookie != nil
      && (1...limits.maximumSetCookieBytes).contains(response.set_cookie_length)
    let selectionIsExact =
      response.set_cookie_selection == PVCURL_SET_COOKIE_SELECTION_LAST_FIELD_WINS
      && (cookieAbsent
        ? response.set_cookie_field_count == 0
        : response.set_cookie_field_count > 0)
    guard selectionIsExact,
      response.effective_url_exact, (100...599).contains(Int(response.http_status)),
      !(300...399).contains(Int(response.http_status)),
      response.http_status != 401, response.http_status != 407,
      response.body_length <= limits.maximumResponseBodyBytes,
      response.body_length == 0 || response.body != nil,
      requireSetCookie ? cookiePresent : (cookieAbsent || cookiePresent)
    else { throw PortalTransportError.invalidResponse }
    let body = try SecureBytes(
      copying: UnsafeRawBufferPointer(start: response.body, count: response.body_length)
    )
    do {
      let setCookie = try response.set_cookie.map {
        try SecureBytes(
          copying: UnsafeRawBufferPointer(start: $0, count: response.set_cookie_length)
        )
      }
      return CurlPortalTransferResult(
        statusCode: Int(response.http_status),
        body: body,
        setCookie: setCookie,
        setCookieProjection: .provenLastFieldWins(
          fieldCount: response.set_cookie_field_count
        )
      )
    } catch {
      body.erase()
      throw error
    }
  }
}

extension CurlPortalTransferInput {
  fileprivate func withCConfiguration<Result>(
    body: UnsafeRawBufferPointer?,
    cookie: UnsafeRawBufferPointer,
    _ operation: (pvcurl_request_config_t) throws -> Result
  ) rethrows -> Result {
    try url.withPVCurlBytes { url in
      try host.withPVCurlBytes { host in
        try accept.withPVCurlBytes { accept in
          try userAgent.withPVCurlBytes { userAgent in
            try contentType.withOptionalPVCurlBytes { contentType in
              try operation(
                pvcurl_request_config_t(
                  method: method == .get ? PVCURL_METHOD_GET : PVCURL_METHOD_POST,
                  require_set_cookie: requireSetCookie,
                  url: url,
                  host_header: host,
                  accept_header: accept,
                  user_agent_header: userAgent,
                  content_type_header: contentType,
                  cookie_header: cookie.pvcurlBytes,
                  body: body?.pvcurlBytes ?? pvcurl_bytes_t(pointer: nil, length: 0),
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

extension Optional where Wrapped == [UInt8] {
  fileprivate func withOptionalPVCurlBytes<Result>(
    _ operation: (pvcurl_bytes_t) throws -> Result
  ) rethrows -> Result {
    switch self {
    case .some(let bytes): return try bytes.withPVCurlBytes(operation)
    case .none: return try operation(pvcurl_bytes_t(pointer: nil, length: 0))
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

final class CurlPortalCancellation: @unchecked Sendable {
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

final class CurlPortalCancellationRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var requests: [ObjectIdentifier: CurlPortalCancellation] = [:]

  func register(_ request: CurlPortalCancellation) {
    lock.withLock { requests[ObjectIdentifier(request)] = request }
  }

  func unregister(_ request: CurlPortalCancellation) {
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
