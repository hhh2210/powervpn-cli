import Foundation

package enum AuthenticatedPortalContextBorrowError: Error, Equatable, Sendable {
  case expired
  case missingIntegrationInfo
  case missingVersion
  case duplicateVersion
  case missingMajorVersion
  case malformedMajorVersion
}

/// A scoped view over version context in the authenticated resource document.
///
/// `majorVersion` is borrowed from app-owned, explicitly erasable XML storage.
/// Gateway is deliberately absent: the installed client resolves `vpnAddress`
/// before helper configuration, so the resource request host is not an exact
/// offline substitute for that value.
package struct AuthenticatedPortalContext: @unchecked Sendable {
  private let integrationInfo: PortalXMLElement
  private let scope: AuthenticatedPortalContextBorrowScope

  init(
    integrationInfo: PortalXMLElement,
    scope: AuthenticatedPortalContextBorrowScope
  ) {
    self.integrationInfo = integrationInfo
    self.scope = scope
  }

  package func withMajorVersionBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    guard scope.isActive else {
      throw AuthenticatedPortalContextBorrowError.expired
    }
    let versions = integrationInfo.childElements.filter { $0.name == "VERSION" }
    guard versions.count <= 1 else {
      throw AuthenticatedPortalContextBorrowError.duplicateVersion
    }
    guard let version = versions.first else {
      throw AuthenticatedPortalContextBorrowError.missingVersion
    }
    guard version.childElements.allSatisfy({ $0.name != "major" }) else {
      throw AuthenticatedPortalContextBorrowError.malformedMajorVersion
    }
    guard let major = version.attribute(named: "major") else {
      throw AuthenticatedPortalContextBorrowError.missingMajorVersion
    }
    return try major.withValueBytes(operation)
  }
}

final class AuthenticatedPortalContextBorrowScope: @unchecked Sendable {
  private let lock = NSLock()
  private let authenticationGeneration: PortalAuthenticationGeneration
  private var active = true

  init(authenticationGeneration: PortalAuthenticationGeneration) {
    self.authenticationGeneration = authenticationGeneration
  }

  var isActive: Bool {
    lock.withLock { active } && authenticationGeneration.isActive
  }

  func invalidate() {
    lock.withLock { active = false }
  }
}
