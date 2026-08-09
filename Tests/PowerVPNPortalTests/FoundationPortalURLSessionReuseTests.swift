import Foundation
import Testing

@testable import PowerVPNPortal

@Suite(.serialized) struct FoundationPortalURLSessionReuseTests {
  @Test func passwordRequestFailsBeforeFoundationOpensTheNetworkSeam() async throws {
    OfflineReuseURLProtocol.state.reset()
    let configuration = URLSessionPortalTransport.makeEphemeralConfiguration(timeout: 5)
    configuration.protocolClasses = [OfflineReuseURLProtocol.self]
    let seam = FoundationPortalURLSession(session: URLSession(configuration: configuration))
    let transport = URLSessionPortalTransport(
      allowedOrigin: try PortalHTTPOrigin(host: "portal.example.invalid", port: 443),
      session: seam,
      maximumResponseBytes: 1_024,
      timeout: 5
    )
    let passwordURL = try #require(
      URL(string: "https://portal.example.invalid/vpn/user/auth/password"))

    do {
      _ = try await transport.perform(request(.post, passwordURL))
      Issue.record("expected Set-Cookie framing rejection")
    } catch let error as PortalTransportError {
      #expect(error == .setCookieFramingUnavailable)
    }
    #expect(OfflineReuseURLProtocol.state.paths.isEmpty)
  }

  @Test(arguments: ["/resource", "/session"])
  func cancelledAuthenticatedRequestDoesNotPreventCleanupLogout(
    _ cancelledPath: String
  ) async throws {
    OfflineReuseURLProtocol.state.reset()
    let configuration = URLSessionPortalTransport.makeEphemeralConfiguration(timeout: 5)
    configuration.protocolClasses = [OfflineReuseURLProtocol.self]
    let session = URLSession(configuration: configuration)
    let seam = FoundationPortalURLSession(session: session)
    let origin = try PortalHTTPOrigin(host: "portal.example.invalid", port: 443)
    let transport = URLSessionPortalTransport(
      allowedOrigin: origin,
      session: seam,
      maximumResponseBytes: 1_024,
      timeout: 5
    )
    let cancelledURL = try #require(
      URL(string: "https://portal.example.invalid\(cancelledPath)"))
    let logoutURL = try #require(
      URL(string: "https://portal.example.invalid/logout"))

    let cancelled = Task {
      try await transport.perform(request(.get, cancelledURL))
    }
    for _ in 0..<10_000 where !OfflineReuseURLProtocol.state.started(cancelledPath) {
      await Task.yield()
    }
    #expect(OfflineReuseURLProtocol.state.started(cancelledPath))
    if cancelledPath == "/resource" {
      cancelled.cancel()
    } else {
      transport.cancel()
    }
    do {
      _ = try await cancelled.value
      Issue.record("expected request cancellation")
    } catch let error as PortalTransportError {
      #expect(error == .cancelled)
    }

    let response = try await transport.perform(request(.post, logoutURL))
    #expect(response.statusCode == 200)
    #expect(response.setCookieProjection == .foundationFoldedValue)
    #expect(try response.withBodyBytes { String(decoding: $0, as: UTF8.self) } == "logout")
    response.erase()
    #expect(OfflineReuseURLProtocol.state.paths == [cancelledPath, "/logout"])
    #expect(OfflineReuseURLProtocol.state.stopCount >= 1)
  }

  private func request(_ method: PortalHTTPMethod, _ url: URL) -> PortalHTTPRequest {
    PortalHTTPRequest(
      method: method,
      url: url,
      headers: try! PortalHTTPHeaders(
        accept: "*/*",
        contentType: nil,
        userAgent: "PowerVPNPortalTests/1"
      )
    )
  }
}

private final class OfflineReuseURLProtocol: URLProtocol, @unchecked Sendable {
  static let state = OfflineReuseURLProtocolState()

  override class func canInit(with _: URLRequest) -> Bool { true }

  override class func canonicalRequest(for request: URLRequest) -> URLRequest {
    request
  }

  override func startLoading() {
    guard let url = request.url,
      let response = HTTPURLResponse(
        url: url,
        statusCode: 200,
        httpVersion: "HTTP/1.1",
        headerFields: url.path == "/logout" ? ["Set-Cookie": "VSG_SESSIONID=synthetic"] : [:]
      )
    else {
      client?.urlProtocol(self, didFailWithError: URLError(.badURL))
      return
    }
    Self.state.recordStart(url.path)
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    guard url.path == "/logout" else { return }
    client?.urlProtocol(self, didLoad: Data("logout".utf8))
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {
    Self.state.recordStop()
  }
}

private final class OfflineReuseURLProtocolState: @unchecked Sendable {
  private let lock = NSLock()
  private var startedPaths: [String] = []
  private var stops = 0

  var paths: [String] { lock.withLock { startedPaths } }
  var stopCount: Int { lock.withLock { stops } }

  func started(_ path: String) -> Bool {
    lock.withLock { startedPaths.contains(path) }
  }

  func reset() {
    lock.withLock {
      startedPaths = []
      stops = 0
    }
  }

  func recordStart(_ path: String) {
    lock.withLock { startedPaths.append(path) }
  }

  func recordStop() {
    lock.withLock { stops += 1 }
  }
}
