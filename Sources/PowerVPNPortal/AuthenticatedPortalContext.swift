import Foundation

package enum AuthenticatedPortalContextBorrowError: Error, Equatable, Sendable {
  case expired
  case missingIntegrationInfo
  case missingVersion
  case duplicateVersion
  case missingMajorVersion
  case malformedMajorVersion
}

/// A scoped view over context bound to one authenticated resource generation.
///
/// `majorVersion` is borrowed from app-owned, explicitly erasable XML storage.
/// Gateway is app-owned storage minted only from the sealed literal-IPv4
/// profile whose vendor resolution path is statically identity-preserving.
package struct AuthenticatedPortalContext: @unchecked Sendable {
  private let integrationInfo: PortalXMLElement
  private let vendorGateway: SecureBytes
  private let scope: AuthenticatedPortalContextBorrowScope

  init(
    integrationInfo: PortalXMLElement,
    vendorGateway: SecureBytes,
    scope: AuthenticatedPortalContextBorrowScope
  ) {
    self.integrationInfo = integrationInfo
    self.vendorGateway = vendorGateway
    self.scope = scope
  }

  package func withVendorGatewayBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    guard scope.isActive else {
      throw AuthenticatedPortalContextBorrowError.expired
    }
    return try vendorGateway.withUnsafeBytes(operation)
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
