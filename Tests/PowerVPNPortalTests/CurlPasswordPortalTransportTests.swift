import CPortalCurl
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct CurlPasswordPortalTransportTests {
  private let origin = try! PortalHTTPOrigin(host: "166.111.143.19", port: 4_443)

  @Test func cRuntimePreflightIsNetworkFreeAndAvailableBeforeCredentialInput() throws {
    _ = try CPortalCurlPasswordDriver()
  }

  @Test func exactPasswordPostReturnsProvenSingleWireHeaderProjection() async throws {
    let driver = RecordingCurlPasswordDriver()
    let transport = try CurlPasswordPortalTransport(
      allowedOrigin: origin,
      driver: driver,
      maximumResponseBytes: 1_024,
      timeout: 7
    )
    let request = try factoryPasswordRequest()
    let body = try #require(request.requestBody)
    let cookie = try #require(request.cookieHeader)

    let response = try await transport.perform(request)

    let snapshot = try #require(driver.snapshot)
    #expect(snapshot.url == "https://166.111.143.19:4443/vpn/user/auth/password")
    #expect(snapshot.host == "166.111.143.19:4443")
    #expect(snapshot.accept == PortalWireContract.accept)
    #expect(snapshot.contentType == PortalWireContract.passwordContentType)
    #expect(
      snapshot.userAgent
        == "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X synthetic-os)"
    )
    #expect(
      snapshot.body
        == "encode='1'&hardware_hash=SERIAL&password=cGFzcw==&terminal_type=mac&type=app&username=dXNlcg=="
    )
    #expect(snapshot.cookie == " VSG_LANGUAGE=zh_CN; ")
    #expect(snapshot.timeoutMilliseconds == 7_000)
    #expect(snapshot.maximumResponseBodyBytes == 1_024)
    #expect(response.statusCode == 200)
    #expect(response.setCookieProjection == .provenSingleWireHeader)
    #expect(try response.withBodyBytes { String(decoding: $0, as: UTF8.self) } == "<ok/>")
    #expect(
      try response.withSetCookieBytes { String(decoding: $0, as: UTF8.self) }
        == "VSG_SESSIONID=synthetic; Secure")
    #expect(body.count == 0)
    #expect(cookie.count == 0)
    response.erase()
  }

  @Test func directNearMissesNeverReachDriverAndEraseInputs() async throws {
    let driver = RecordingCurlPasswordDriver()
    let transport = try CurlPasswordPortalTransport(allowedOrigin: origin, driver: driver)
    let requests = [
      directPasswordRequest(
        url: "https://166.111.143.19:4443/vpn/user/auth/password?extra=1"
      ),
      directPasswordRequest(
        url: "https://synthetic:value@166.111.143.19:4443/vpn/user/auth/password"
      ),
      directPasswordRequest(body: "encode='1'&factory_bypass=body"),
      directPasswordRequest(cookie: "VSG_LANGUAGE=en_US"),
      directPasswordRequest(userAgent: "PowerVPNPortalTests/forged"),
    ]

    for request in requests {
      let body = try #require(request.requestBody)
      let cookie = try #require(request.cookieHeader)
      await expectCurlError(.invalidRequest) {
        try await transport.perform(request)
      }
      #expect(body.count == 0)
      #expect(cookie.count == 0)
    }

    #expect(driver.snapshot == nil)
  }

  @Test func taskCancellationReachesBlockingDriverAndErasesInputs() async throws {
    let driver = BlockingCurlPasswordDriver()
    let transport = try CurlPasswordPortalTransport(allowedOrigin: origin, driver: driver)
    let request = try factoryPasswordRequest()
    let body = try #require(request.requestBody)
    let cookie = try #require(request.cookieHeader)
    let task = Task { try await transport.perform(request) }
    for _ in 0..<1_000 where !driver.started { await Task.yield() }
    #expect(driver.started)

    task.cancel()
    await expectCurlError(.cancelled) { try await task.value }

    #expect(driver.cancelled)
    #expect(body.count == 0)
    #expect(cookie.count == 0)
  }

  @Test func transportCancellationReachesActiveBlockingDriver() async throws {
    let driver = BlockingCurlPasswordDriver()
    let transport = try CurlPasswordPortalTransport(allowedOrigin: origin, driver: driver)
    let request = try factoryPasswordRequest()
    let task = Task { try await transport.perform(request) }
    for _ in 0..<1_000 where !driver.started { await Task.yield() }
    #expect(driver.started)

    transport.cancel()
    await expectCurlError(.cancelled) { try await task.value }
    #expect(driver.cancelled)
  }

  @Test func cStatusesMapToClosedValueFreeTransportErrors() {
    let cases: [(pvcurl_status_t, PortalTransportError?)] = [
      (PVCURL_STATUS_OK, nil),
      (PVCURL_STATUS_INVALID_ARGUMENT, .invalidRequest),
      (PVCURL_STATUS_SETUP_FAILED, .unavailable),
      (PVCURL_STATUS_TRUST_REJECTED, .trustRejected),
      (PVCURL_STATUS_REDIRECT_REJECTED, .redirectRejected),
      (PVCURL_STATUS_AUTHENTICATION_REJECTED, .authenticationChallengeRejected),
      (PVCURL_STATUS_HEADER_FRAMING_REJECTED, .invalidResponse),
      (PVCURL_STATUS_RESPONSE_TOO_LARGE, .responseTooLarge),
      (PVCURL_STATUS_CANCELLED, .cancelled),
      (PVCURL_STATUS_TIMED_OUT, .timedOut),
      (PVCURL_STATUS_UNAVAILABLE, .unavailable),
    ]
    for (status, expected) in cases {
      #expect(CPortalCurlPasswordDriver.normalizedStatus(status) == expected)
    }
  }

  @Test func foreignDriverErrorsAreCollapsedWithoutPayload() async throws {
    let sentinel = "foreign-curl-error-secret-sentinel"
    let driver = FailingCurlPasswordDriver(error: CurlForeignError(value: sentinel))
    let transport = try CurlPasswordPortalTransport(allowedOrigin: origin, driver: driver)
    do {
      _ = try await transport.perform(factoryPasswordRequest())
      Issue.record("expected normalized failure")
    } catch let error as PortalTransportError {
      #expect(error == .unavailable)
      #expect(!error.description.contains(sentinel))
      #expect(!String(reflecting: error).contains(sentinel))
    }
  }

  private func factoryPasswordRequest() throws -> PortalHTTPRequest {
    let factory = try syntheticRequestFactory()
    let credentials = try syntheticCredentials()
    let serial = try syntheticSerial()
    defer {
      credentials.erase()
      serial.erase()
    }
    return try factory.makePasswordRequest(
      credentials: credentials,
      platformSerial: serial
    )
  }

  private func directPasswordRequest(
    url: String = "https://166.111.143.19:4443/vpn/user/auth/password",
    body: String = "encode='1'&hardware_hash=SERIAL",
    cookie: String = " VSG_LANGUAGE=zh_CN; ",
    userAgent: String = "VSG-libCurl/0.9.9 PowerVPN/3.2.1 (Mac OS X synthetic-os)"
  ) -> PortalHTTPRequest {
    PortalHTTPRequest(
      method: .post,
      url: URL(string: url)!,
      headers: try! PortalHTTPHeaders(
        accept: PortalWireContract.accept,
        contentType: PortalWireContract.passwordContentType,
        userAgent: userAgent
      ),
      body: try! SecureBytes(copying: Array(body.utf8)),
      cookieHeader: try! SecureBytes(copying: Array(cookie.utf8))
    )
  }
}

private struct CurlDriverSnapshot: Equatable, Sendable {
  let url: String
  let host: String
  let accept: String
  let userAgent: String
  let contentType: String
  let body: String
  let cookie: String
  let timeoutMilliseconds: UInt32
  let maximumResponseBodyBytes: Int
}

private final class RecordingCurlPasswordDriver: @unchecked Sendable, CurlPasswordDriving {
  private let lock = NSLock()
  private var observed: CurlDriverSnapshot?

  var snapshot: CurlDriverSnapshot? { lock.withLock { observed } }

  func perform(
    input: CurlPasswordTransferInput,
    body: UnsafeRawBufferPointer,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPasswordCancellation
  ) throws -> CurlPasswordTransferResult {
    lock.withLock {
      observed = CurlDriverSnapshot(
        url: String(decoding: input.url, as: UTF8.self),
        host: String(decoding: input.host, as: UTF8.self),
        accept: String(decoding: input.accept, as: UTF8.self),
        userAgent: String(decoding: input.userAgent, as: UTF8.self),
        contentType: String(decoding: input.contentType, as: UTF8.self),
        body: String(decoding: body, as: UTF8.self),
        cookie: String(decoding: cookie, as: UTF8.self),
        timeoutMilliseconds: input.limits.timeoutMilliseconds,
        maximumResponseBodyBytes: input.limits.maximumResponseBodyBytes
      )
    }
    return CurlPasswordTransferResult(
      statusCode: 200,
      body: try SecureBytes(copying: Array("<ok/>".utf8)),
      setCookie: try SecureBytes(copying: Array("VSG_SESSIONID=synthetic; Secure".utf8))
    )
  }
}

private final class BlockingCurlPasswordDriver: @unchecked Sendable, CurlPasswordDriving {
  private let condition = NSCondition()
  private var didStart = false
  private var didCancel = false

  var started: Bool { condition.withLock { didStart } }
  var cancelled: Bool { condition.withLock { didCancel } }

  func perform(
    input: CurlPasswordTransferInput,
    body: UnsafeRawBufferPointer,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPasswordCancellation
  ) throws -> CurlPasswordTransferResult {
    cancellation.install { [self] in
      condition.withLock {
        didCancel = true
        condition.broadcast()
      }
    }
    defer { cancellation.clear() }
    condition.lock()
    didStart = true
    condition.broadcast()
    while !didCancel { condition.wait() }
    condition.unlock()
    throw PortalTransportError.cancelled
  }
}

private struct FailingCurlPasswordDriver: CurlPasswordDriving {
  let error: any Error & Sendable

  func perform(
    input: CurlPasswordTransferInput,
    body: UnsafeRawBufferPointer,
    cookie: UnsafeRawBufferPointer,
    cancellation: CurlPasswordCancellation
  ) throws -> CurlPasswordTransferResult {
    throw error
  }
}

private struct CurlForeignError: Error, Sendable {
  let value: String
}

private func expectCurlError(
  _ expected: PortalTransportError,
  operation: () async throws -> PortalHTTPResponse
) async {
  do {
    _ = try await operation()
    Issue.record("expected curl transport failure")
  } catch let error as PortalTransportError {
    #expect(error == expected)
  } catch {
    Issue.record("unexpected error category")
  }
}
