import Foundation

final class PortalAuthenticationGeneration: @unchecked Sendable {
  private let lock = NSLock()
  private var active = true

  var isActive: Bool { lock.withLock { active } }
  func invalidate() { lock.withLock { active = false } }
}

package enum AuthenticatedPortalResourceCategory: String, CaseIterable, Sendable {
  case remote = "REMOTE_RESOURCE"
  case networkConnect = "NC_RESOURCE"
  case tcpUDP = "TCPUDP_RESOURCE"
  case web = "WEB_RESOURCE"
  case webVPN = "WEBVPN_RESOURCE"
  case ipsec = "IPSEC_RESOURCE"
}

package struct AuthenticatedPortalCategoryObservation: Equatable, Sendable {
  package let category: AuthenticatedPortalResourceCategory
  package let nodeCount: Int
}

package struct AuthenticatedPortalSnapshotDescriptor: Equatable, Sendable {
  package let authenticatedPortalSessionPresent: Bool
  package let integrationInfoPresent: Bool
  package let resourceListPresent: Bool
  package let categoryObservations: [AuthenticatedPortalCategoryObservation]

  package var observedCategoryNodeCount: Int {
    categoryObservations.reduce(0) { $0 + $1.nodeCount }
  }
}

package enum AuthenticatedPortalSnapshotError: Error, Equatable, Sendable {
  case inactiveAuthenticationGeneration
  case missingResourceList
  case duplicateResourceList
  case inaccessible
  case erased
}

package enum AuthenticatedPortalResourceBorrowError: Error, Equatable, Sendable {
  case expired
  case notScalar
  case missingAttribute
}

/// A package-scoped view over app-owned copies in one authenticated
/// `RESOURCE_LIST` tree. Scalar and attribute storage is explicitly erased by
/// the snapshot. Any value a package consumer copies out is outside that
/// erasure boundary, so production consumers should retain only value-free
/// shape metadata.
package struct AuthenticatedPortalResourceElement: @unchecked Sendable {
  package let name: String

  private let element: PortalXMLElement
  private let scope: AuthenticatedPortalResourceBorrowScope

  fileprivate init(
    element: PortalXMLElement,
    scope: AuthenticatedPortalResourceBorrowScope
  ) {
    name = element.name
    self.element = element
    self.scope = scope
  }

  package var childElements: [AuthenticatedPortalResourceElement] {
    get throws {
      try requireActiveBorrow()
      return element.childElements.map {
        AuthenticatedPortalResourceElement(element: $0, scope: scope)
      }
    }
  }

  package var attributeNames: [String] {
    get throws {
      try requireActiveBorrow()
      return element.attributes.map(\.name)
    }
  }

  package func withScalarBytes<Result>(
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try requireActiveBorrow()
    guard element.attributes.isEmpty, element.childElements.isEmpty else {
      throw AuthenticatedPortalResourceBorrowError.notScalar
    }
    let text = element.contents.compactMap { content -> SecureBytes? in
      guard case .text(let bytes) = content else { return nil }
      return bytes
    }
    guard text.count <= 1 else {
      throw AuthenticatedPortalResourceBorrowError.notScalar
    }
    guard let value = text.first else {
      return try operation(UnsafeRawBufferPointer(start: nil, count: 0))
    }
    return try value.withUnsafeBytes(operation)
  }

  package func withAttributeValueBytes<Result>(
    named name: String,
    _ operation: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try requireActiveBorrow()
    guard let attribute = element.attribute(named: name) else {
      throw AuthenticatedPortalResourceBorrowError.missingAttribute
    }
    return try attribute.withValueBytes(operation)
  }

  private func requireActiveBorrow() throws {
    guard scope.isActive else {
      throw AuthenticatedPortalResourceBorrowError.expired
    }
  }
}

/// A package-scoped, memory-only capability tying one authenticated portal
/// generation to the resource document returned in that same workflow.
///
/// The explicit erasure claim covers only app-owned `SecureBytes` copies in the
/// resource tree. It does not cover XMLParser/Foundation private buffers or
/// copies deliberately created by a package consumer. Portal cookie material
/// remains private to the cookie jar.
package final class AuthenticatedPortalSnapshot: @unchecked Sendable {
  private let lock = NSRecursiveLock()
  private let authenticationGeneration: PortalAuthenticationGeneration
  private var resourceDocument: PortalXMLDocument?
  private var vendorGateway: SecureBytes?
  package let descriptor: AuthenticatedPortalSnapshotDescriptor
  /// Non-secret package identity for selecting one resource from this snapshot.
  package let selectionGenerationID = UUID()

  init(
    resourceDocument: PortalXMLDocument,
    authenticationGeneration: PortalAuthenticationGeneration,
    vendorGateway: SecureBytes
  ) throws {
    guard authenticationGeneration.isActive else {
      resourceDocument.erase()
      vendorGateway.erase()
      throw AuthenticatedPortalSnapshotError.inactiveAuthenticationGeneration
    }
    do {
      descriptor = try describeAuthenticatedPortalSnapshot(resourceDocument)
      self.authenticationGeneration = authenticationGeneration
      self.resourceDocument = resourceDocument
      self.vendorGateway = vendorGateway
    } catch {
      resourceDocument.erase()
      vendorGateway.erase()
      throw error
    }
  }

  package var isErased: Bool {
    lock.withLock { resourceDocument == nil && vendorGateway == nil }
  }

  package var isAccessible: Bool {
    lock.withLock {
      resourceDocument != nil && vendorGateway != nil && authenticationGeneration.isActive
    }
  }

  func withResourceDocument<Result>(
    _ operation: (PortalXMLDocument) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      guard let resourceDocument else { throw AuthenticatedPortalSnapshotError.erased }
      guard vendorGateway != nil else { throw AuthenticatedPortalSnapshotError.erased }
      guard authenticationGeneration.isActive else {
        throw AuthenticatedPortalSnapshotError.inaccessible
      }
      return try operation(resourceDocument)
    }
  }

  /// Borrows the exact `RESOURCE_LIST` tree bound to this snapshot. The view
  /// and every child view expire when `operation` returns, even if retained.
  package func withResourceTree<Result>(
    _ operation: (AuthenticatedPortalResourceElement) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      guard let resourceDocument else { throw AuthenticatedPortalSnapshotError.erased }
      guard vendorGateway != nil else { throw AuthenticatedPortalSnapshotError.erased }
      guard authenticationGeneration.isActive else {
        throw AuthenticatedPortalSnapshotError.inaccessible
      }
      guard let integration = try LeadSecPortalProfile.integrationInfo(resourceDocument) else {
        throw AuthenticatedPortalSnapshotError.missingResourceList
      }
      let lists = integration.childElements.filter { $0.name == "RESOURCE_LIST" }
      guard lists.count <= 1 else {
        throw AuthenticatedPortalSnapshotError.duplicateResourceList
      }
      guard let resourceList = lists.first else {
        throw AuthenticatedPortalSnapshotError.missingResourceList
      }
      let scope = AuthenticatedPortalResourceBorrowScope(
        authenticationGeneration: authenticationGeneration
      )
      defer { scope.invalidate() }
      return try operation(
        AuthenticatedPortalResourceElement(element: resourceList, scope: scope)
      )
    }
  }

  /// Borrows context proven to originate in this generation's resource reply.
  package func withPortalContext<Result>(
    _ operation: (AuthenticatedPortalContext) throws -> Result
  ) throws -> Result {
    try lock.withLock {
      guard let resourceDocument else { throw AuthenticatedPortalSnapshotError.erased }
      guard let vendorGateway else { throw AuthenticatedPortalSnapshotError.erased }
      guard authenticationGeneration.isActive else {
        throw AuthenticatedPortalSnapshotError.inaccessible
      }
      guard let integration = try LeadSecPortalProfile.integrationInfo(resourceDocument) else {
        throw AuthenticatedPortalContextBorrowError.missingIntegrationInfo
      }
      let scope = AuthenticatedPortalContextBorrowScope(
        authenticationGeneration: authenticationGeneration
      )
      defer { scope.invalidate() }
      return try operation(
        AuthenticatedPortalContext(
          integrationInfo: integration,
          vendorGateway: vendorGateway,
          scope: scope
        ))
    }
  }

  package func erase() {
    lock.withLock {
      resourceDocument?.erase()
      vendorGateway?.erase()
      resourceDocument = nil
      vendorGateway = nil
    }
  }

  deinit {
    erase()
  }
}

private final class AuthenticatedPortalResourceBorrowScope: @unchecked Sendable {
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

package protocol AuthenticatedPortalSnapshotConsuming: Sendable {
  /// The snapshot is valid only for the duration of this call. Implementations
  /// must complete any helper-control experiment before returning.
  func consume(_ snapshot: AuthenticatedPortalSnapshot) async throws
}

package struct DiscardingAuthenticatedPortalSnapshotConsumer:
  AuthenticatedPortalSnapshotConsuming
{
  package init() {}

  package func consume(_: AuthenticatedPortalSnapshot) async throws {}
}
