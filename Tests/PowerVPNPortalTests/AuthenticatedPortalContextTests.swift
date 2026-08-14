import Dispatch
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct AuthenticatedPortalContextTests {
  @Test func majorVersionIsScopedToTheAuthenticatedResourceGeneration() throws {
    let factory = try authenticatedContextFactory()
    let request = try factory.makeResourceRequest()
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: try contextDocument()
    )
    defer {
      request.erase()
      snapshot.erase()
      factory.eraseSession()
    }
    var escaped: AuthenticatedPortalContext?

    let shape = try snapshot.withPortalContext { context in
      escaped = context
      #expect((context as Any) is any Encodable == false)
      return try context.withMajorVersionBytes {
        (
          matchesProvenMajor: $0.elementsEqual([0x32]),
          byteCount: $0.count
        )
      }
    }

    #expect(shape.matchesProvenMajor)
    #expect(shape.byteCount == 1)
    #expect(throws: AuthenticatedPortalContextBorrowError.expired) {
      _ = try escaped?.withMajorVersionBytes { $0.count }
    }
  }

  @Test func generationInvalidationRevokesContextWithoutClaimingErasure() throws {
    let factory = try authenticatedContextFactory()
    let request = try factory.makeResourceRequest()
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: try contextDocument()
    )
    defer {
      request.erase()
      snapshot.erase()
      factory.eraseSession()
    }

    try snapshot.withPortalContext { context in
      factory.eraseSession()
      #expect(throws: AuthenticatedPortalContextBorrowError.expired) {
        _ = try context.withMajorVersionBytes { $0.count }
      }
    }

    #expect(!snapshot.isAccessible)
    #expect(!snapshot.isErased)
    #expect(throws: AuthenticatedPortalSnapshotError.inaccessible) {
      _ = try snapshot.withPortalContext { _ in true }
    }
    snapshot.erase()
    #expect(snapshot.isErased)
  }

  @Test func malformedOrAmbiguousVersionContextFailsClosed() throws {
    try expectContextError(
      .missingIntegrationInfo,
      xml: "<ROOT/>"
    )
    try expectMajorError(
      .missingVersion,
      xml: "<ROOT><INTERGRATION_INFO><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
    )
    try expectMajorError(
      .duplicateVersion,
      xml:
        "<ROOT><INTERGRATION_INFO><VERSION/><VERSION/><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
    )
    try expectMajorError(
      .missingMajorVersion,
      xml:
        "<ROOT><INTERGRATION_INFO><VERSION minor=\"0\"/><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
    )
    try expectMajorError(
      .malformedMajorVersion,
      xml:
        "<ROOT><INTERGRATION_INFO><VERSION><major>2</major></VERSION><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
    )
  }

  @Test func eraseWaitsForContextBorrowThenZeroesOwnedMajorStorage() async throws {
    let observation = ContextZeroObservation()
    let factory = try authenticatedContextFactory()
    let request = try factory.makeResourceRequest()
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: try contextDocument { observation.record($0) }
    )
    defer {
      request.erase()
      snapshot.erase()
      factory.eraseSession()
    }
    #expect(observation.snapshots.isEmpty)
    let state = ConcurrentContextBorrowState()
    let releaseBorrow = DispatchSemaphore(value: 0)

    let borrow = Task.detached {
      try snapshot.withPortalContext { context in
        try context.withMajorVersionBytes { bytes in
          state.append(.borrowEntered)
          releaseBorrow.wait()
          state.append(.borrowLeaving)
          return bytes.count
        }
      }
    }
    let borrowDidEnter = await waitForContext { state.contains(.borrowEntered) }
    #expect(borrowDidEnter)
    let erase = Task.detached {
      state.append(.eraseStarted)
      snapshot.erase()
      state.append(.eraseFinished)
    }
    let eraseDidStart = await waitForContext { state.contains(.eraseStarted) }
    #expect(eraseDidStart)

    releaseBorrow.signal()
    #expect(try await borrow.value == 1)
    await erase.value
    #expect(
      state.events == [.borrowEntered, .eraseStarted, .borrowLeaving, .eraseFinished]
    )
    #expect(snapshot.isErased)
    #expect(observation.snapshots.count == 1)
    #expect(observation.snapshots[0].allSatisfy { $0 == 0 })
  }
}

private func authenticatedContextFactory() throws -> PortalRequestFactory {
  let factory = try syntheticRequestFactory()
  let response = PortalHTTPResponse(
    statusCode: 200,
    body: try SecureBytes(copying: Array(acceptedLoginXML.utf8)),
    setCookieHeader: try SecureBytes(
      copying: Array("VSG_SESSIONID=context-test; Path=/; Secure".utf8)
    ),
    setCookieProjection: .provenLastFieldWins(fieldCount: 1)
  )
  defer { response.erase() }
  try factory.acceptPasswordSession(
    from: response,
    passwordURL: URL(string: "https://166.111.143.19:4443/vpn/user/auth/password")!
  )
  return factory
}

private func contextDocument(
  eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil
) throws -> PortalXMLDocument {
  let xml =
    "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/>"
    + "<RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
  return try PortalXMLStructuralParser(eraseObserver: eraseObserver).parse(
    consuming: SecureBytes(copying: Array(xml.utf8))
  )
}

private func expectContextError(
  _ expected: AuthenticatedPortalContextBorrowError,
  xml: String
) throws {
  let (factory, request, snapshot) = try contextFixture(xml: xml)
  defer {
    request.erase()
    snapshot.erase()
    factory.eraseSession()
  }
  #expect(throws: expected) {
    _ = try snapshot.withPortalContext { _ in true }
  }
}

private func expectMajorError(
  _ expected: AuthenticatedPortalContextBorrowError,
  xml: String
) throws {
  let (factory, request, snapshot) = try contextFixture(xml: xml)
  defer {
    request.erase()
    snapshot.erase()
    factory.eraseSession()
  }
  #expect(throws: expected) {
    _ = try snapshot.withPortalContext { context in
      try context.withMajorVersionBytes { $0.count }
    }
  }
}

private func contextFixture(
  xml: String
) throws -> (PortalRequestFactory, PortalHTTPRequest, AuthenticatedPortalSnapshot) {
  let factory = try authenticatedContextFactory()
  let request = try factory.makeResourceRequest()
  let document = try PortalXMLStructuralParser().parse(
    consuming: SecureBytes(copying: Array(xml.utf8))
  )
  return (
    factory,
    request,
    try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: document
    )
  )
}

private final class ContextZeroObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [[UInt8]] = []

  var snapshots: [[UInt8]] { lock.withLock { storage } }
  func record(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock { storage.append(Array(bytes)) }
  }
}

private final class ConcurrentContextBorrowState: @unchecked Sendable {
  enum Event: Equatable {
    case borrowEntered
    case eraseStarted
    case borrowLeaving
    case eraseFinished
  }

  private let lock = NSLock()
  private var recorded: [Event] = []

  func append(_ event: Event) { lock.withLock { recorded.append(event) } }
  func contains(_ event: Event) -> Bool { lock.withLock { recorded.contains(event) } }
  var events: [Event] { lock.withLock { recorded } }
}

private func waitForContext(
  _ predicate: () -> Bool
) async -> Bool {
  for _ in 0..<10_000 {
    if predicate() { return true }
    await Task.yield()
  }
  return predicate()
}
