import Foundation

@testable import PowerVPNPortal

struct SyntheticRequestSnapshot: Equatable, Sendable {
  let method: PortalHTTPMethod
  let url: String
  let accept: String
  let contentType: String?
  let userAgent: String
  let body: String?
  let cookie: String?
}

enum SyntheticTransportStep: Sendable {
  case response(status: Int, body: String, setCookie: String? = nil)
  case failure(PortalTransportError)
  case suspendUntilCancelled
}

actor SyntheticPortalTransport: PortalTransporting {
  private var steps: [SyntheticTransportStep]
  private var captured: [SyntheticRequestSnapshot] = []
  private var retainedRequests: [PortalHTTPRequest] = []
  private var retainedResponses: [PortalHTTPResponse] = []

  init(_ steps: [SyntheticTransportStep]) {
    self.steps = steps
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    guard request.begin() else { throw PortalTransportError.invalidRequest }
    retainedRequests.append(request)
    captured.append(try snapshot(request))
    guard !steps.isEmpty else { throw PortalTransportError.unavailable }
    switch steps.removeFirst() {
    case .failure(let error):
      throw error
    case .suspendUntilCancelled:
      try await Task.sleep(nanoseconds: UInt64.max)
      throw PortalTransportError.unavailable
    case .response(let status, let body, let setCookie):
      let secureCookie = try setCookie.map { try SecureBytes(copying: Array($0.utf8)) }
      let response = PortalHTTPResponse(
        statusCode: status,
        body: try SecureBytes(copying: Array(body.utf8)),
        setCookieHeader: secureCookie,
        setCookieProjection: secureCookie == nil ? .unavailableOrAmbiguous : .provenSingleWireHeader
      )
      retainedResponses.append(response)
      return response
    }
  }

  nonisolated func cancel() {}

  func snapshots() -> [SyntheticRequestSnapshot] { captured }

  func remainingStepCount() -> Int { steps.count }

  func allOwnedRequestMaterialErased() -> Bool {
    retainedRequests.allSatisfy {
      ($0.requestBody?.count ?? 0) == 0 && ($0.cookieHeader?.count ?? 0) == 0
    }
  }

  func allOwnedResponseMaterialErased() -> Bool {
    retainedResponses.allSatisfy {
      $0.bodyByteCount == 0 && ($0.setCookieByteCount ?? 0) == 0
    }
  }

  private func snapshot(_ request: PortalHTTPRequest) throws -> SyntheticRequestSnapshot {
    SyntheticRequestSnapshot(
      method: request.method,
      url: request.url.absoluteString,
      accept: request.headers.accept,
      contentType: request.headers.contentType,
      userAgent: request.headers.userAgent,
      body: try request.requestBody.map { bytes in
        try bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
      },
      cookie: try request.cookieHeader.map { bytes in
        try bytes.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
      }
    )
  }
}

actor CancellableGatePortalSleeper: PortalSleeping {
  private var entered = false

  func sleep(seconds _: UInt64) async throws {
    entered = true
    try await Task.sleep(nanoseconds: UInt64.max)
  }

  func hasEntered() -> Bool { entered }
}

actor SyntheticPortalSleeper: PortalSleeping {
  enum Behavior: Sendable { case succeed, cancel, fail }

  private let behavior: Behavior
  private var recordedSeconds: [UInt64] = []

  init(_ behavior: Behavior = .succeed) {
    self.behavior = behavior
  }

  func sleep(seconds: UInt64) async throws {
    recordedSeconds.append(seconds)
    switch behavior {
    case .succeed: return
    case .cancel: throw CancellationError()
    case .fail: throw PortalTransportError.unavailable
    }
  }

  func sleeps() -> [UInt64] { recordedSeconds }
}

final class SyntheticEraseObserver: @unchecked Sendable {
  private let lock = NSLock()
  private var observations = 0
  private var allZero = true

  func observe(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock {
      observations += 1
      allZero = allZero && bytes.allSatisfy { $0 == 0 }
    }
  }

  var result: (count: Int, allZero: Bool) {
    lock.withLock { (observations, allZero) }
  }
}

func syntheticPortalProfile() -> InstalledPortalProfile {
  InstalledPortalProfile(
    origin: URL(string: "https://166.111.143.19:4443")!,
    portalVersion: "2.0",
    selectionSemantics: .latestPrimaryKeyFallback,
    vendorLanguageIndex: 0
  )
}

func syntheticRequestFactory() throws -> PortalRequestFactory {
  try PortalRequestFactory(
    profile: syntheticPortalProfile(),
    operatingSystemVersion: "synthetic-os"
  )
}

func syntheticLoginWorkflow(
  _ factory: PortalRequestFactory,
  _ transport: SyntheticPortalTransport,
  _ sleeper: any PortalSleeping,
  logoutBounder: any PortalLogoutBounding = TimedDetachedPortalLogoutBounder()
) throws -> PortalLoginWorkflow {
  try PortalLoginWorkflow(
    factory: factory,
    transport: transport,
    sleeper: sleeper,
    logoutBounder: logoutBounder
  )
}

func syntheticCredentials(
  observer: SyntheticEraseObserver? = nil
) throws -> PortalCredentials {
  let eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  if let observer {
    eraseObserver = { bytes in observer.observe(bytes) }
  } else {
    eraseObserver = nil
  }
  let username = try SecureBytes(
    copying: Array("user".utf8),
    eraseObserver: eraseObserver
  )
  let password = try SecureBytes(
    copying: Array("pass".utf8),
    eraseObserver: eraseObserver
  )
  return PortalCredentials(username: username, password: password)
}

func syntheticSerial(
  observer: SyntheticEraseObserver? = nil
) throws -> SecureBytes {
  let eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  if let observer {
    eraseObserver = { bytes in observer.observe(bytes) }
  } else {
    eraseObserver = nil
  }
  return try SecureBytes(
    copying: Array("SERIAL".utf8),
    eraseObserver: eraseObserver
  )
}

let acceptedLoginXML = "<ROOT><RESPONSE><RESULT><code>0</code></RESULT></RESPONSE></ROOT>"
let acceptedResourceXML = "<ROOT><INTERGRATION_INFO><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
let acceptedSessionXML = "<ROOT><RESPONSE><RESULT><code>0</code></RESULT></RESPONSE></ROOT>"
let invalidSessionXML =
  "<ROOT><RESPONSE><RESULT><code>0x80000014</code></RESULT></RESPONSE></ROOT>"
let syntheticSessionCookie = "VSG_SESSIONID=synthetic"
