import Foundation

enum PortalTransportError: Error, Equatable, Sendable, CustomStringConvertible {
  case invalidOrigin
  case invalidRequest
  case insecureTransport
  case originMismatch
  case redirectRejected
  case authenticationChallengeRejected
  case trustRejected
  case invalidResponse
  case responseTooLarge
  case cancelled
  case timedOut
  case unavailable

  var description: String {
    switch self {
    case .invalidOrigin: "invalid portal origin"
    case .invalidRequest: "invalid portal request"
    case .insecureTransport: "portal HTTPS is required"
    case .originMismatch: "portal origin mismatch"
    case .redirectRejected: "portal redirect rejected"
    case .authenticationChallengeRejected: "portal authentication challenge rejected"
    case .trustRejected: "portal TLS trust rejected"
    case .invalidResponse: "invalid portal response"
    case .responseTooLarge: "portal response exceeded the bounded limit"
    case .cancelled: "portal request cancelled"
    case .timedOut: "portal request timed out"
    case .unavailable: "portal transport unavailable"
    }
  }
}

struct PortalHTTPOrigin: Equatable, Sendable {
  let host: String
  let port: Int

  init(host: String, port: Int) throws {
    guard (1...65_535).contains(port), Self.isValidHost(host) else {
      throw PortalTransportError.invalidOrigin
    }
    self.host = host.lowercased()
    self.port = port
  }

  func matches(_ url: URL) -> Bool {
    guard url.scheme?.lowercased() == "https",
      url.user == nil,
      url.password == nil,
      let candidateHost = url.host?.lowercased()
    else { return false }
    return candidateHost == host && (url.port ?? 443) == port
  }

  var authority: String {
    let renderedHost = host.contains(":") ? "[\(host)]" : host
    return port == 443 ? renderedHost : "\(renderedHost):\(port)"
  }

  private static func isValidHost(_ host: String) -> Bool {
    guard !host.isEmpty, host == host.trimmingCharacters(in: .whitespacesAndNewlines),
      !host.hasSuffix("."), host.utf8.count <= 253,
      !host.unicodeScalars.contains(where: { $0.value == 0 })
    else { return false }
    var components = URLComponents()
    components.scheme = "https"
    components.host = host
    components.port = 443
    return components.url?.host != nil
  }
}

enum PortalHTTPMethod: String, Sendable {
  case get = "GET"
  case post = "POST"
}

struct PortalHTTPHeaders: Equatable, Sendable {
  let accept: String
  let contentType: String?
  let userAgent: String

  init(accept: String, contentType: String?, userAgent: String) throws {
    guard Self.isSafeValue(accept), Self.isSafeValue(userAgent),
      contentType.map(Self.isSafeValue) ?? true
    else { throw PortalTransportError.invalidRequest }
    self.accept = accept
    self.contentType = contentType
    self.userAgent = userAgent
  }

  private static func isSafeValue(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.allSatisfy { (0x20...0x7e).contains($0) }
  }
}

/// A one-shot request. Passing a body transfers its erasure ownership to this
/// request; completion, validation failure, cancellation, and deinit all erase
/// it. The only secret header is an erasable cookie; its unavoidable transient
/// URLRequest/CF copy is outside the app-owned zeroization claim.
final class PortalHTTPRequest: @unchecked Sendable {
  let method: PortalHTTPMethod
  let url: URL
  let headers: PortalHTTPHeaders
  let requestBody: SecureBytes?
  let cookieHeader: SecureBytes?

  private let lock = NSLock()
  private var consumed = false

  init(
    method: PortalHTTPMethod,
    url: URL,
    headers: PortalHTTPHeaders,
    body: SecureBytes? = nil,
    cookieHeader: SecureBytes? = nil
  ) {
    self.method = method
    self.url = url
    self.headers = headers
    requestBody = body
    self.cookieHeader = cookieHeader
  }

  func begin() -> Bool {
    lock.withLock {
      guard !consumed else { return false }
      consumed = true
      return true
    }
  }

  func erase() {
    requestBody?.erase()
    cookieHeader?.erase()
  }

  deinit {
    erase()
  }
}

/// A response body remains in explicitly erasable storage and is deliberately
/// non-Codable. Status is retained; response URL and headers are not.
final class PortalHTTPResponse: @unchecked Sendable {
  let statusCode: Int
  private let body: SecureBytes
  private let setCookieHeader: SecureBytes?

  init(statusCode: Int, body: SecureBytes, setCookieHeader: SecureBytes? = nil) {
    self.statusCode = statusCode
    self.body = body
    self.setCookieHeader = setCookieHeader
  }

  var bodyByteCount: Int { body.count }
  var setCookieByteCount: Int? { setCookieHeader?.count }

  func withBodyBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try body.withUnsafeBytes(operation)
  }

  func withSetCookieBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result? {
    try setCookieHeader?.withUnsafeBytes(operation)
  }

  func erase() {
    body.erase()
    setCookieHeader?.erase()
  }

  deinit {
    erase()
  }
}

protocol PortalTransporting: Sendable {
  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse
  func cancel()
}

struct PortalSessionResponseHead: Sendable {
  let statusCode: Int
  let finalURL: URL
  let setCookieHeader: SecureBytes?
}

struct PortalSessionByteStream: Sendable {
  let head: PortalSessionResponseHead
  let bytes: AsyncThrowingStream<UInt8, Error>
  let cancel: @Sendable () -> Void
}

protocol PortalURLSessionPerforming: Sendable {
  func open(_ request: URLRequest) async throws -> PortalSessionByteStream
  func cancelAll()
}

final class SecureResponseAccumulator {
  private let storage: UnsafeMutableRawPointer
  private let capacity: Int
  private var count = 0
  private var erased = false

  init(capacity: Int) throws {
    guard let storage = malloc(max(capacity, 1)) else {
      throw PortalTransportError.unavailable
    }
    self.storage = storage
    self.capacity = capacity
  }

  func append(_ byte: UInt8) -> Bool {
    guard !erased, count < capacity else { return false }
    storage.storeBytes(of: byte, toByteOffset: count, as: UInt8.self)
    count += 1
    return true
  }

  func finish() throws -> SecureBytes {
    guard !erased else { throw PortalTransportError.unavailable }
    let result = try SecureBytes(
      copying: UnsafeRawBufferPointer(start: storage, count: count)
    )
    erase()
    return result
  }

  deinit {
    erase()
    free(storage)
  }

  private func erase() {
    guard !erased else { return }
    if count > 0 { _ = memset_s(storage, count, 0, count) }
    erased = true
    count = 0
  }
}

final class SecureBodyInputStream: InputStream, @unchecked Sendable {
  private let bytes: SecureBytes
  private var offset = 0
  private var status: Stream.Status = .notOpen
  private var failure: Error?

  init(bytes: SecureBytes) {
    self.bytes = bytes
    super.init(data: Data())
  }

  override func open() {
    if status == .notOpen { status = .open }
  }

  override func close() {
    status = .closed
  }

  override var streamStatus: Stream.Status { status }
  override var streamError: Error? { failure }
  override var hasBytesAvailable: Bool { status == .open && offset < bytes.count }

  override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength length: Int) -> Int {
    guard status == .open, length > 0 else { return status == .atEnd ? 0 : -1 }
    do {
      let copied = try bytes.withUnsafeBytes { source -> Int in
        let remaining = source.count - offset
        guard remaining > 0 else { return 0 }
        let copied = min(remaining, length)
        _ = memcpy(buffer, source.baseAddress!.advanced(by: offset), copied)
        offset += copied
        return copied
      }
      if copied == 0 { status = .atEnd }
      return copied
    } catch {
      failure = PortalTransportError.invalidRequest
      status = .error
      return -1
    }
  }

  override func getBuffer(
    _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    length: UnsafeMutablePointer<Int>
  ) -> Bool {
    false
  }
}
