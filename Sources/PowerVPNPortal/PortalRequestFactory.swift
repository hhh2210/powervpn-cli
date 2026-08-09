import Darwin
import Foundation

enum PortalRequestFactoryError: Error, Equatable, Sendable {
  case invalidProfile
  case invalidURL
}

/// Produces only the four requests proven for the sealed R2 portal profile.
/// There is no initializer accepting a host, port, path, query, or body.
struct PortalRequestFactory: Sendable {
  private let profile: InstalledPortalProfile
  private let headers: PortalHTTPHeaders
  private let cookieJar: LeadSecPortalCookieJar

  init(
    profile: InstalledPortalProfile,
    operatingSystemVersion: String
  ) throws {
    guard Self.isExactOrigin(profile.origin), profile.portalVersion == "2.0" else {
      throw PortalRequestFactoryError.invalidProfile
    }
    self.profile = profile
    headers = try PortalHTTPHeaders(
      accept: PortalWireContract.accept,
      contentType: nil,
      userAgent: PortalWireContract.vendorUserAgent(
        operatingSystemVersion: operatingSystemVersion
      )
    )
    cookieJar = try LeadSecPortalCookieJar(profile: profile)
  }

  func makePasswordRequest(
    credentials: PortalCredentials,
    platformSerial: SecureBytes
  ) throws -> PortalHTTPRequest {
    let url = try makeURL(path: PortalWireContract.passwordPath, query: nil)
    let cookie = try cookieJar.makeOutgoingCookieHeader()
    do {
      let body = try PortalPasswordBodyBuilder.encode1(
        credentials: credentials,
        platformSerial: platformSerial
      )
      let passwordHeaders = try PortalHTTPHeaders(
        accept: headers.accept,
        contentType: PortalWireContract.passwordContentType,
        userAgent: headers.userAgent
      )
      return PortalHTTPRequest(
        method: .post,
        url: url,
        headers: passwordHeaders,
        body: body,
        cookieHeader: cookie
      )
    } catch {
      cookie.erase()
      throw error
    }
  }

  func makeResourceRequest() throws -> PortalHTTPRequest {
    try makeRequest(
      method: .get,
      path: PortalWireContract.resourcePath,
      query: "version=\(profile.portalVersion)"
    )
  }

  func makeSessionCheckRequest() throws -> PortalHTTPRequest {
    try makeRequest(
      method: .get,
      path: PortalWireContract.sessionCheckPath,
      query: "key=hostid"
    )
  }

  func makeLogoutRequest() throws -> PortalHTTPRequest {
    try makeRequest(method: .post, path: PortalWireContract.logoutPath, query: nil)
  }

  func acceptPasswordSession(
    from response: PortalHTTPResponse,
    passwordURL: URL
  ) throws {
    let setCookie = try response.withSetCookieBytes { bytes in
      try SecureBytes(copying: bytes)
    }
    defer { setCookie?.erase() }

    var transientURL = Array(passwordURL.absoluteString.utf8)
    defer {
      transientURL.withUnsafeMutableBytes { bytes in
        if !bytes.isEmpty {
          _ = memset_s(bytes.baseAddress!, bytes.count, 0, bytes.count)
        }
      }
    }
    let secureURL = try SecureBytes(copying: transientURL)
    defer { secureURL.erase() }
    try cookieJar.acceptPasswordResponse(
      setCookieHeader: setCookie,
      projection: .foundationSingleValue,
      passwordURL: secureURL
    )
  }

  func eraseSession() {
    cookieJar.erase()
  }

  var retainedSessionByteCount: Int {
    cookieJar.retainedSessionByteCount
  }

  private func makeRequest(
    method: PortalHTTPMethod,
    path: String,
    query: String?
  ) throws -> PortalHTTPRequest {
    PortalHTTPRequest(
      method: method,
      url: try makeURL(path: path, query: query),
      headers: headers,
      cookieHeader: try cookieJar.makeOutgoingCookieHeader()
    )
  }

  private func makeURL(path: String, query: String?) throws -> URL {
    guard
      var components = URLComponents(
        url: profile.origin,
        resolvingAgainstBaseURL: false
      )
    else { throw PortalRequestFactoryError.invalidURL }
    components.path = path
    components.percentEncodedQuery = query
    guard let url = components.url, url.path == path,
      url.query == query, url.fragment == nil,
      url.user == nil, url.password == nil
    else { throw PortalRequestFactoryError.invalidURL }
    return url
  }

  private static func isExactOrigin(_ url: URL) -> Bool {
    url.absoluteString == "https://166.111.143.19:4443"
      && url.scheme == "https"
      && url.host == "166.111.143.19"
      && url.port == 4_443
      && url.user == nil
      && url.password == nil
      && url.query == nil
      && url.fragment == nil
      && url.path.isEmpty
  }
}
