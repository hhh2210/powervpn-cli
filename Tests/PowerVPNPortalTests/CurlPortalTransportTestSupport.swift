import Foundation
import Testing

@testable import PowerVPNPortal

struct CurlDriverSnapshot: Equatable, Sendable {
  let method: PortalHTTPMethod
  let requireSetCookie: Bool
  let url: String
  let host: String
  let accept: String
  let userAgent: String
  let contentType: String?
  let body: String?
  let cookie: String
  let timeoutMilliseconds: UInt32
  let maximumResponseBodyBytes: Int
}

final class RecordingCurlPortalDriver: @unchecked Sendable, CurlPortalDriving {
  private let lock = NSLock()
  private var observed: [CurlDriverSnapshot] = []

  var snapshot: CurlDriverSnapshot? { lock.withLock { observed.last } }
  var snapshots: [CurlDriverSnapshot] { lock.withLock { observed } }

  func perform(
    input: CurlPortalTransferInput,
    body: UnsafeRawBufferPointer?,
    cookie: UnsafeRawBufferPointer,
    cancellation _: CurlPortalCancellation
  ) throws -> CurlPortalTransferResult {
    lock.withLock {
      observed.append(
        CurlDriverSnapshot(
          method: input.method,
          requireSetCookie: input.requireSetCookie,
          url: String(decoding: input.url, as: UTF8.self),
          host: String(decoding: input.host, as: UTF8.self),
          accept: String(decoding: input.accept, as: UTF8.self),
          userAgent: String(decoding: input.userAgent, as: UTF8.self),
          contentType: input.contentType.map { String(decoding: $0, as: UTF8.self) },
          body: body.map { String(decoding: $0, as: UTF8.self) },
          cookie: String(decoding: cookie, as: UTF8.self),
          timeoutMilliseconds: input.limits.timeoutMilliseconds,
          maximumResponseBodyBytes: input.limits.maximumResponseBodyBytes
        ))
    }

    let setCookie =
      input.contentType == nil
      ? nil
      : try SecureBytes(copying: Array("VSG_SESSIONID=synthetic; Secure".utf8))
    return CurlPortalTransferResult(
      statusCode: 200,
      body: try SecureBytes(copying: Array("<ok/>".utf8)),
      setCookie: setCookie,
      setCookieProjection: .provenLastFieldWins(fieldCount: setCookie == nil ? 0 : 1)
    )
  }
}

final class LoginBoundaryCurlPortalDriver: @unchecked Sendable, CurlPortalDriving {
  private let lock = NSLock()
  private let passwordXML: String
  private let passwordCookie: String?
  private let passwordSetCookieFieldCount: UInt32
  private var observedPaths: [String] = []
  private var observedRequirements: [Bool] = []
  private var observedCookies: [String] = []

  init(
    passwordXML: String,
    passwordCookie: String?,
    passwordSetCookieFieldCount: UInt32? = nil
  ) {
    self.passwordXML = passwordXML
    self.passwordCookie = passwordCookie
    self.passwordSetCookieFieldCount =
      passwordSetCookieFieldCount ?? (passwordCookie == nil ? 0 : 1)
  }

  var paths: [String] { lock.withLock { observedPaths } }
  var requirements: [Bool] { lock.withLock { observedRequirements } }
  var cookies: [String] { lock.withLock { observedCookies } }

  func perform(
    input: CurlPortalTransferInput,
    body _: UnsafeRawBufferPointer?,
    cookie: UnsafeRawBufferPointer,
    cancellation _: CurlPortalCancellation
  ) throws -> CurlPortalTransferResult {
    guard let url = URL(string: String(decoding: input.url, as: UTF8.self)) else {
      throw PortalTransportError.invalidRequest
    }
    lock.withLock {
      observedPaths.append(url.path)
      observedRequirements.append(input.requireSetCookie)
      observedCookies.append(String(decoding: cookie, as: UTF8.self))
    }

    let response: (body: String, cookie: String?, fieldCount: UInt32)
    switch url.path {
    case PortalWireContract.passwordPath:
      guard !input.requireSetCookie || passwordCookie != nil else {
        throw PortalTransportError.invalidResponse
      }
      response = (passwordXML, passwordCookie, passwordSetCookieFieldCount)
    case PortalWireContract.resourcePath:
      response = (acceptedResourceXML, nil, 0)
    case PortalWireContract.sessionCheckPath:
      response = (acceptedSessionXML, nil, 0)
    case PortalWireContract.logoutPath:
      response = ("", nil, 0)
    default:
      throw PortalTransportError.invalidRequest
    }
    return CurlPortalTransferResult(
      statusCode: 200,
      body: try SecureBytes(copying: Array(response.body.utf8)),
      setCookie: try response.cookie.map { try SecureBytes(copying: Array($0.utf8)) },
      setCookieProjection: .provenLastFieldWins(fieldCount: response.fieldCount)
    )
  }
}

final class BlockingCurlPortalDriver: @unchecked Sendable, CurlPortalDriving {
  private let condition = NSCondition()
  private var didStart = false
  private var didCancel = false

  var started: Bool { condition.withLock { didStart } }
  var cancelled: Bool { condition.withLock { didCancel } }

  func perform(
    input _: CurlPortalTransferInput,
    body _: UnsafeRawBufferPointer?,
    cookie _: UnsafeRawBufferPointer,
    cancellation: CurlPortalCancellation
  ) throws -> CurlPortalTransferResult {
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

struct FailingCurlPortalDriver: CurlPortalDriving {
  let error: any Error & Sendable

  func perform(
    input _: CurlPortalTransferInput,
    body _: UnsafeRawBufferPointer?,
    cookie _: UnsafeRawBufferPointer,
    cancellation _: CurlPortalCancellation
  ) throws -> CurlPortalTransferResult {
    throw error
  }
}

struct CurlForeignError: Error, Sendable {
  let value: String
}

func expectCurlError(
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
