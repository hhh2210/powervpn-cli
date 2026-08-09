import Foundation

enum PortalAuthenticationDisposition: Equatable, Sendable {
  case useSystemCredential
  case reject
}

enum PortalRedirectDisposition: Equatable, Sendable {
  case reject
}

struct PortalTrustPolicy: Sendable {
  private let exactHost: String

  init(profile: InstalledPortalProfile) {
    exactHost = profile.origin.host ?? ""
  }

  init(exactHost: String) {
    self.exactHost = exactHost
  }

  func authenticationDisposition(
    authenticationMethod: String,
    host: String,
    serverTrustAvailable: Bool,
    evaluateSystemTrust: () -> Bool
  ) -> PortalAuthenticationDisposition {
    guard authenticationMethod == NSURLAuthenticationMethodServerTrust,
      serverTrustAvailable,
      host == exactHost,
      evaluateSystemTrust()
    else {
      return .reject
    }
    return .useSystemCredential
  }

  /// Redirects are not part of the observed portal dialect. Rejecting both
  /// same-origin and cross-origin redirects avoids normalizing server behavior.
  func redirectDisposition(
    from _: URL,
    to _: URL
  ) -> PortalRedirectDisposition {
    .reject
  }
}
