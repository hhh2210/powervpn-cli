import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct URLSessionPortalTransportTests {
  private let origin = try! PortalHTTPOrigin(host: "portal.example.invalid", port: 443)

  @Test func ephemeralConfigurationDisablesPersistentHTTPState() {
    let configuration = URLSessionPortalTransport.makeEphemeralConfiguration(timeout: 9)

    #expect(configuration.identifier == nil)
    #expect(configuration.urlCache == nil)
    #expect(configuration.requestCachePolicy == .reloadIgnoringLocalCacheData)
    #expect(configuration.httpCookieStorage == nil)
    #expect(!configuration.httpShouldSetCookies)
    #expect(configuration.urlCredentialStorage == nil)
    #expect(!configuration.waitsForConnectivity)
    #expect(configuration.timeoutIntervalForRequest == 9)
    #expect(configuration.timeoutIntervalForResource == 9)
    #expect(configuration.httpMaximumConnectionsPerHost == 1)
  }

  @Test func successStreamsRequestAndReturnsOwnedBoundedResponse() async throws {
    let url = try #require(URL(string: "https://portal.example.invalid/login"))
    let session = ScriptedPortalSession(
      .response(
        status: 200,
        finalURL: url,
        bytes: [0x00, 0xff, 0x41],
        setCookie: Array("session=synthetic; Secure".utf8)
      ))
    let body = try SecureBytes(copying: Array("synthetic-request-body".utf8))
    let cookie = try SecureBytes(copying: Array("session=prior".utf8))
    let request = makeRequest(.post, url: url, body: body, cookieHeader: cookie)
    let response = try await transport(session: session).perform(request)

    #expect(session.openCount == 1)
    #expect(session.lastMethod == "POST")
    #expect(session.lastBody == Array("synthetic-request-body".utf8))
    #expect(session.lastHeaders?["Host"] == "portal.example.invalid")
    #expect(session.lastHeaders?["Accept"] == "*/*")
    #expect(session.lastHeaders?["Content-Type"] == "text/xml")
    #expect(session.lastHeaders?["User-Agent"] == "PowerVPNPortalTests/1")
    #expect(session.lastHeaders?["Cookie"] == "session=prior")
    #expect(body.count == 0)
    #expect(cookie.count == 0)
    #expect(response.statusCode == 200)
    #expect(try response.withBodyBytes { Array($0) } == [0x00, 0xff, 0x41])
    #expect(
      try response.withSetCookieBytes { String(decoding: $0, as: UTF8.self) }
        == "session=synthetic; Secure")
    response.erase()
    #expect(response.bodyByteCount == 0)
    #expect(response.setCookieByteCount == 0)
    #expect(session.lastResponseCookie?.count == 0)
  }

  @Test func httpAndWrongOriginFailBeforeOpeningASession() async throws {
    let session = ScriptedPortalSession(.failure(URLError(.cannotConnectToHost)))
    let insecure = makeRequest(
      .get,
      url: try #require(URL(string: "http://portal.example.invalid/check")))
    let wrongOrigin = makeRequest(
      .get,
      url: try #require(URL(string: "https://other.example.invalid/check")))

    await expectError(.insecureTransport) {
      try await transport(session: session).perform(insecure)
    }
    await expectError(.originMismatch) {
      try await transport(session: session).perform(wrongOrigin)
    }
    #expect(session.openCount == 0)
  }

  @Test func redirectsAndChangedFinalURLsAreRejected() async throws {
    let source = try #require(URL(string: "https://portal.example.invalid/login"))
    let redirected = try #require(URL(string: "https://portal.example.invalid/next"))
    let redirectSession = ScriptedPortalSession(
      .response(
        status: 302,
        finalURL: source,
        bytes: [],
        setCookie: Array("session=must-be-erased".utf8)
      ))
    let changedSession = ScriptedPortalSession(
      .response(status: 200, finalURL: redirected, bytes: [], setCookie: nil))

    await expectError(.redirectRejected) {
      try await transport(session: redirectSession).perform(
        makeRequest(.post, url: source))
    }
    await expectError(.redirectRejected) {
      try await transport(session: changedSession).perform(
        makeRequest(.post, url: source))
    }
    #expect(redirectSession.streamCancelCount == 1)
    #expect(changedSession.streamCancelCount == 1)
    #expect(redirectSession.lastResponseCookie?.count == 0)
  }

  @Test func httpAuthenticationChallengesFailClosed() async throws {
    let url = try #require(URL(string: "https://portal.example.invalid/login"))
    let session = ScriptedPortalSession(.failure(URLError(.userAuthenticationRequired)))

    await expectError(.authenticationChallengeRejected) {
      try await transport(session: session).perform(makeRequest(.post, url: url))
    }
  }

  @Test func systemTrustFailureIsNormalizedWithoutUnderlyingDetails() async throws {
    let url = try #require(URL(string: "https://portal.example.invalid/login"))
    let session = ScriptedPortalSession(.failure(URLError(.serverCertificateUntrusted)))

    await expectError(.trustRejected) {
      try await transport(session: session).perform(makeRequest(.post, url: url))
    }
  }

  @Test func responseCapCancelsTheStreamAtTheFirstExcessByte() async throws {
    let url = try #require(URL(string: "https://portal.example.invalid/catalog"))
    let session = ScriptedPortalSession(
      .response(status: 200, finalURL: url, bytes: [1, 2, 3, 4, 5], setCookie: nil))

    await expectError(.responseTooLarge) {
      try await transport(session: session, maximumBytes: 4).perform(
        makeRequest(.get, url: url))
    }
    #expect(session.streamCancelCount == 1)
  }

  @Test func taskCancellationIsNormalizedWithoutInvalidatingTheSession() async throws {
    let url = try #require(URL(string: "https://portal.example.invalid/check"))
    let session = ScriptedPortalSession(.suspend)
    let task = Task {
      try await transport(session: session).perform(makeRequest(.get, url: url))
    }
    for _ in 0..<100 where session.openCount == 0 { await Task.yield() }
    task.cancel()

    do {
      _ = try await task.value
      Issue.record("expected cancellation")
    } catch let error as PortalTransportError {
      #expect(error == .cancelled)
    }
    #expect(session.openCount == 1)
  }

  @Test func foreignErrorsCannotEchoTheirSecretPayload() async throws {
    let sentinel = "foreign-error-secret-sentinel"
    let url = try #require(URL(string: "https://portal.example.invalid/check"))
    let session = ScriptedPortalSession(.failure(ForeignSecretError(value: sentinel)))
    do {
      _ = try await transport(session: session).perform(makeRequest(.get, url: url))
      Issue.record("expected normalized failure")
    } catch let error as PortalTransportError {
      #expect(error == .unavailable)
      #expect(!error.description.contains(sentinel))
      #expect(!String(reflecting: error).contains(sentinel))
    }
  }

  private func transport(
    session: ScriptedPortalSession,
    maximumBytes: Int = 1_024
  ) -> URLSessionPortalTransport {
    URLSessionPortalTransport(
      allowedOrigin: origin,
      session: session,
      maximumResponseBytes: maximumBytes,
      timeout: 5
    )
  }

  private func makeRequest(
    _ method: PortalHTTPMethod,
    url: URL,
    body: SecureBytes? = nil,
    cookieHeader: SecureBytes? = nil
  ) -> PortalHTTPRequest {
    PortalHTTPRequest(
      method: method,
      url: url,
      headers: try! PortalHTTPHeaders(
        accept: "*/*",
        contentType: method == .post ? "text/xml" : nil,
        userAgent: "PowerVPNPortalTests/1"
      ),
      body: body,
      cookieHeader: cookieHeader
    )
  }
}

private func expectError(
  _ expected: PortalTransportError,
  operation: () async throws -> PortalHTTPResponse
) async {
  do {
    _ = try await operation()
    Issue.record("expected portal transport failure")
  } catch let error as PortalTransportError {
    #expect(error == expected)
  } catch {
    Issue.record("unexpected error category")
  }
}

private enum ScriptedSessionBehavior {
  case response(status: Int, finalURL: URL, bytes: [UInt8], setCookie: [UInt8]?)
  case failure(Error)
  case suspend
}

private final class ScriptedPortalSession: @unchecked Sendable, PortalURLSessionPerforming {
  let passwordSetCookieProjection =
    LeadSecSetCookieProjection.provenLastFieldWins(fieldCount: 1)
  private let lock = NSLock()
  private let behavior: ScriptedSessionBehavior
  private var opens = 0
  private var streamCancellations = 0
  private var method: String?
  private var body: [UInt8]?
  private var headers: [String: String]?
  private var responseCookie: SecureBytes?

  init(_ behavior: ScriptedSessionBehavior) {
    self.behavior = behavior
  }

  var openCount: Int { lock.withLock { opens } }
  var streamCancelCount: Int { lock.withLock { streamCancellations } }
  var lastMethod: String? { lock.withLock { method } }
  var lastBody: [UInt8]? { lock.withLock { body } }
  var lastHeaders: [String: String]? { lock.withLock { headers } }
  var lastResponseCookie: SecureBytes? { lock.withLock { responseCookie } }

  func open(_ request: URLRequest) async throws -> PortalSessionByteStream {
    let observedBody = readBody(request.httpBodyStream)
    lock.withLock {
      opens += 1
      method = request.httpMethod
      body = observedBody
      headers = request.allHTTPHeaderFields
    }
    switch behavior {
    case .failure(let error): throw error
    case .suspend:
      try await Task.sleep(for: .seconds(60))
      throw CancellationError()
    case .response(let status, let finalURL, let bytes, let cookieBytes):
      let cookie = try cookieBytes.map { try SecureBytes(copying: $0) }
      lock.withLock { responseCookie = cookie }
      let stream = AsyncThrowingStream<UInt8, Error> { continuation in
        for byte in bytes { continuation.yield(byte) }
        continuation.finish()
      }
      return PortalSessionByteStream(
        head: PortalSessionResponseHead(
          statusCode: status,
          finalURL: finalURL,
          setCookieHeader: cookie,
          setCookieProjection: cookie == nil
            ? .unavailableOrAmbiguous : .provenLastFieldWins(fieldCount: 1)
        ),
        bytes: stream,
        cancel: { [weak self] in
          self?.lock.withLock { self?.streamCancellations += 1 }
        }
      )
    }
  }

  private func readBody(_ stream: InputStream?) -> [UInt8]? {
    guard let stream else { return nil }
    var result: [UInt8] = []
    var buffer = [UInt8](repeating: 0, count: 32)
    stream.open()
    defer { stream.close() }
    while true {
      let count = buffer.withUnsafeMutableBufferPointer {
        stream.read($0.baseAddress!, maxLength: $0.count)
      }
      guard count > 0 else { return count == 0 ? result : nil }
      result.append(contentsOf: buffer.prefix(count))
    }
  }
}

private struct ForeignSecretError: Error, Sendable {
  let value: String
}
