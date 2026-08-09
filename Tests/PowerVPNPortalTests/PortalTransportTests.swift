import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalTransportTests {
  @Test func originRequiresAClosedHostAndPort() throws {
    #expect(throws: PortalTransportError.invalidOrigin) {
      _ = try PortalHTTPOrigin(host: "", port: 443)
    }
    #expect(throws: PortalTransportError.invalidOrigin) {
      _ = try PortalHTTPOrigin(host: "portal.example.invalid", port: 0)
    }
    #expect(throws: PortalTransportError.invalidOrigin) {
      _ = try PortalHTTPOrigin(host: " portal.example.invalid", port: 443)
    }
    #expect(throws: PortalTransportError.invalidOrigin) {
      _ = try PortalHTTPOrigin(host: "portal.example.invalid.", port: 443)
    }
  }

  @Test func originMatchesOnlyHTTPSHostAndEffectivePort() throws {
    let origin = try PortalHTTPOrigin(host: "Portal.Example.Invalid", port: 443)

    #expect(origin.matches(try #require(URL(string: "https://portal.example.invalid/path"))))
    #expect(!origin.matches(try #require(URL(string: "http://portal.example.invalid/path"))))
    #expect(!origin.matches(try #require(URL(string: "https://other.example.invalid/path"))))
    #expect(!origin.matches(try #require(URL(string: "https://portal.example.invalid:4443/path"))))
    #expect(!origin.matches(try #require(URL(string: "https://user@portal.example.invalid/path"))))
  }

  @Test func requestOwnsAndErasesTransferredBody() throws {
    let observation = ByteEraseObservation()
    let body = try SecureBytes(copying: Array("request-body-sentinel".utf8)) {
      observation.record($0)
    }
    do {
      let url = try #require(URL(string: "https://portal.example.invalid/login"))
      let request = PortalHTTPRequest(
        method: .post,
        url: url,
        headers: try testHeaders(),
        body: body
      )
      #expect(request.begin())
      #expect(!request.begin())
    }

    #expect(body.count == 0)
    #expect(observation.snapshots.count == 1)
    #expect(observation.snapshots[0].allSatisfy { $0 == 0 })
  }

  @Test func responseIsNonCodableOwnedStorageWithCascadeErase() throws {
    let observation = ByteEraseObservation()
    let body = try SecureBytes(copying: [0x00, 0xff, 0x41]) {
      observation.record($0)
    }
    let response = PortalHTTPResponse(statusCode: 200, body: body)

    #expect(response.bodyByteCount == 3)
    #expect(try response.withBodyBytes { Array($0) } == [0x00, 0xff, 0x41])
    response.erase()
    response.erase()

    #expect(response.bodyByteCount == 0)
    #expect(observation.snapshots == [[0, 0, 0]])
  }

  @Test func bodyInputStreamNeverExposesItsBackingPointer() throws {
    let secure = try SecureBytes(copying: [0x00, 0xff, 0x41, 0x42])
    let stream = SecureBodyInputStream(bytes: secure)
    var output = [UInt8](repeating: 0, count: 4)
    stream.open()

    let first = output.withUnsafeMutableBufferPointer {
      stream.read($0.baseAddress!, maxLength: 2)
    }
    let second = output.withUnsafeMutableBufferPointer {
      stream.read($0.baseAddress!.advanced(by: 2), maxLength: 2)
    }
    let end = output.withUnsafeMutableBufferPointer {
      stream.read($0.baseAddress!, maxLength: 1)
    }

    #expect(first == 2)
    #expect(second == 2)
    #expect(end == 0)
    #expect(output == [0x00, 0xff, 0x41, 0x42])
    #expect(stream.streamStatus == .atEnd)
    secure.erase()
  }

  @Test func everyErrorDescriptionIsClosedAndValueFree() {
    let sentinel = "transport-error-secret-sentinel"
    let errors: [PortalTransportError] = [
      .invalidOrigin, .invalidRequest, .insecureTransport, .originMismatch,
      .redirectRejected, .authenticationChallengeRejected, .trustRejected,
      .setCookieFramingUnavailable, .invalidResponse, .responseTooLarge,
      .cancelled, .timedOut, .unavailable,
    ]
    for error in errors {
      #expect(!error.description.contains(sentinel))
      #expect(!String(reflecting: error).contains(sentinel))
    }
  }

  @Test func onlyTheAllowlistedSetCookieHeaderIsCopiedToSecureStorage() throws {
    let url = try #require(URL(string: "https://portal.example.invalid/login"))
    let response = try #require(
      HTTPURLResponse(
        url: url,
        statusCode: 200,
        httpVersion: "HTTP/1.1",
        headerFields: ["Set-Cookie": "session=synthetic; Secure", "X-Ignored": "sentinel"]
      ))
    let extracted = try FoundationPortalURLSession.copySetCookie(response)
    let cookie = try #require(extracted)

    #expect(
      try cookie.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
        == "session=synthetic; Secure")
    #expect(
      try cookie.withUnsafeBytes { String(decoding: $0, as: UTF8.self).contains("sentinel") }
        == false)
    cookie.erase()
  }

  @Test func controlBytesInSetCookieFailClosedWithoutRetainingOtherHeaders() throws {
    let url = try #require(URL(string: "https://portal.example.invalid/login"))
    let response = try #require(
      HTTPURLResponse(
        url: url,
        statusCode: 200,
        httpVersion: "HTTP/1.1",
        headerFields: ["Set-Cookie": "session=bad\u{7f}"]
      ))
    #expect(throws: PortalTransportError.invalidResponse) {
      _ = try FoundationPortalURLSession.copySetCookie(response)
    }
  }
}

private func testHeaders() throws -> PortalHTTPHeaders {
  try PortalHTTPHeaders(
    accept: "*/*",
    contentType: "text/xml",
    userAgent: "PowerVPNPortalTests/1"
  )
}

private final class ByteEraseObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [[UInt8]] = []

  var snapshots: [[UInt8]] { lock.withLock { storage } }

  func record(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock { storage.append(Array(bytes)) }
  }
}
