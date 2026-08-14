import Dispatch
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct AuthenticatedPortalSnapshotTests {
  @Test func resourceDocumentIsBoundToOneAuthenticatedGeneration() throws {
    let factory = try syntheticRequestFactory()
    let loginResponse = try passwordResponse(
      cookie: "VSG_SESSIONID=synthetic-token; Path=/; Secure"
    )
    defer { loginResponse.erase() }
    try factory.acceptPasswordSession(
      from: loginResponse,
      passwordURL: URL(
        string: "https://166.111.143.19:4443/vpn/user/auth/password"
      )!
    )
    let resourceRequest = try factory.makeResourceRequest()
    defer { resourceRequest.erase() }
    let document = try resourceDocument()
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: resourceRequest,
      resourceDocument: document
    )
    defer {
      snapshot.erase()
      factory.eraseSession()
    }
    let selectionGenerationID = snapshot.selectionGenerationID

    let helperSessionIDShape = try snapshot.withResourceTree { list in
      let networkConnect = try #require(
        try list.childElements.first { $0.name == "NC_RESOURCE" }
      )
      let tunnel = try #require(
        try networkConnect.childElements.first { $0.name == "TUNNEL" }
      )
      let ike = try #require(try tunnel.childElements.first { $0.name == "IKE" })
      let client = try #require(try ike.childElements.first { $0.name == "CLIENT" })
      let id = try #require(try client.childElements.first { $0.name == "id" })
      return try id.withScalarBytes { (present: !$0.isEmpty, byteCount: $0.count) }
    }
    #expect(helperSessionIDShape.present)
    #expect(helperSessionIDShape.byteCount == 17)
    #expect(snapshot.descriptor.authenticatedPortalSessionPresent)
    #expect(snapshot.descriptor.integrationInfoPresent)
    #expect(snapshot.descriptor.resourceListPresent)
    #expect(snapshot.descriptor.observedCategoryNodeCount == 2)
    #expect(
      snapshot.descriptor.categoryObservations.first {
        $0.category == .networkConnect
      }?.nodeCount == 1
    )
    #expect((snapshot as Any) is any Encodable == false)
    #expect(snapshot.isAccessible)
    #expect(!snapshot.isErased)

    snapshot.erase()
    #expect(snapshot.isErased)
    #expect(!snapshot.isAccessible)
    #expect(snapshot.selectionGenerationID == selectionGenerationID)
    #expect(throws: AuthenticatedPortalSnapshotError.erased) {
      _ = try snapshot.withResourceTree { $0.name }
    }
  }

  @Test func aResourceProofFromAnotherAuthenticationCannotMint() throws {
    let first = try authenticatedFactory(cookie: "VSG_SESSIONID=first;")
    let second = try authenticatedFactory(cookie: "VSG_SESSIONID=second;")
    defer {
      first.eraseSession()
      second.eraseSession()
    }
    let firstRequest = try first.makeResourceRequest()
    defer { firstRequest.erase() }
    let document = try resourceDocument()

    #expect(throws: LeadSecPortalCookieJarError.generationMismatch) {
      _ = try second.mintAuthenticatedSnapshot(
        resourceRequest: firstRequest,
        resourceDocument: document
      )
    }
    document.erase()
  }

  @Test func invalidatingTheSessionInvalidatesOutstandingSnapshot() throws {
    let factory = try authenticatedFactory(cookie: "VSG_SESSIONID=synthetic;")
    let request = try factory.makeResourceRequest()
    defer { request.erase() }
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: resourceDocument()
    )
    defer { snapshot.erase() }

    factory.eraseSession()

    #expect(!snapshot.isErased)
    #expect(!snapshot.isAccessible)
    #expect(throws: AuthenticatedPortalSnapshotError.inaccessible) {
      _ = try snapshot.withResourceTree { $0.name }
    }
    snapshot.erase()
    #expect(snapshot.isErased)
  }

  @Test func staleResourceProofCannotMintAfterSessionErasure() throws {
    let factory = try authenticatedFactory(cookie: "VSG_SESSIONID=synthetic;")
    let request = try factory.makeResourceRequest()
    defer { request.erase() }
    factory.eraseSession()
    let document = try resourceDocument()
    defer { document.erase() }

    #expect(throws: LeadSecPortalCookieJarError.generationMismatch) {
      _ = try factory.mintAuthenticatedSnapshot(
        resourceRequest: request,
        resourceDocument: document
      )
    }
  }

  @Test func resourceTreeBorrowExpiresAtClosureReturn() throws {
    let factory = try authenticatedFactory(cookie: "VSG_SESSIONID=synthetic;")
    let request = try factory.makeResourceRequest()
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: resourceDocument()
    )
    defer {
      request.erase()
      snapshot.erase()
      factory.eraseSession()
    }
    var escaped: AuthenticatedPortalResourceElement?

    let observedName = try snapshot.withResourceTree { list in
      #expect(list.name == "RESOURCE_LIST")
      let networkConnect = try list.childElements.first { $0.name == "NC_RESOURCE" }
      #expect(try networkConnect?.attributeNames == ["authority"])
      #expect(
        try networkConnect?.withAttributeValueBytes(named: "authority") {
          String(decoding: $0, as: UTF8.self)
        } == "1"
      )
      let name = try networkConnect?.childElements.first { $0.name == "name" }
      escaped = name
      return try name?.withScalarBytes { String(decoding: $0, as: UTF8.self) }
    }

    #expect(observedName == "synthetic")
    #expect(throws: AuthenticatedPortalResourceBorrowError.expired) {
      _ = try escaped?.withScalarBytes { $0.count }
    }
  }

  @Test func eraseWaitsForActiveResourceBorrowAndThenClosesAccess() async throws {
    let factory = try authenticatedFactory(cookie: "VSG_SESSIONID=borrowed;")
    let request = try factory.makeResourceRequest()
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: resourceDocument()
    )
    defer {
      request.erase()
      snapshot.erase()
      factory.eraseSession()
    }
    let state = ConcurrentSnapshotBorrowState()
    let releaseBorrow = DispatchSemaphore(value: 0)

    let borrow = Task.detached {
      try snapshot.withResourceTree { list in
        state.append(.borrowEntered)
        releaseBorrow.wait()
        state.append(.borrowLeaving)
        return list.name
      }
    }
    let borrowDidEnter = await waitUntil { state.contains(.borrowEntered) }
    #expect(borrowDidEnter)
    let erase = Task.detached {
      state.append(.eraseStarted)
      snapshot.erase()
      state.append(.eraseFinished)
    }
    let eraseDidStart = await waitUntil { state.contains(.eraseStarted) }
    #expect(eraseDidStart)

    releaseBorrow.signal()
    #expect(try await borrow.value == "RESOURCE_LIST")
    await erase.value
    #expect(
      state.events == [.borrowEntered, .eraseStarted, .borrowLeaving, .eraseFinished]
    )
    #expect(snapshot.isErased)
  }

  @Test func duplicateResourceListFailsClosed() throws {
    let factory = try authenticatedFactory(cookie: "VSG_SESSIONID=synthetic;")
    defer { factory.eraseSession() }
    let request = try factory.makeResourceRequest()
    defer { request.erase() }
    let parser = try PortalXMLStructuralParser()
    let document = try parser.parse(
      consuming: SecureBytes(
        copying: Array(
          "<ROOT><INTERGRATION_INFO><RESOURCE_LIST/><RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
            .utf8
        )
      )
    )

    #expect(throws: AuthenticatedPortalSnapshotError.duplicateResourceList) {
      _ = try factory.mintAuthenticatedSnapshot(
        resourceRequest: request,
        resourceDocument: document
      )
    }
  }

  private func authenticatedFactory(
    cookie: String
  ) throws -> PortalRequestFactory {
    let factory = try syntheticRequestFactory()
    let response = try passwordResponse(cookie: cookie)
    defer { response.erase() }
    try factory.acceptPasswordSession(
      from: response,
      passwordURL: URL(
        string: "https://166.111.143.19:4443/vpn/user/auth/password"
      )!
    )
    return factory
  }

  private func passwordResponse(cookie: String) throws -> PortalHTTPResponse {
    PortalHTTPResponse(
      statusCode: 200,
      body: try SecureBytes(copying: Array(acceptedLoginXML.utf8)),
      setCookieHeader: try SecureBytes(copying: Array(cookie.utf8)),
      setCookieProjection: .provenLastFieldWins(fieldCount: 1)
    )
  }

  private func resourceDocument() throws -> PortalXMLDocument {
    let xml =
      "<ROOT><INTERGRATION_INFO><RESOURCE_LIST><NC_RESOURCE authority=\"1\"><TUNNEL><IKE><CLIENT><id>helper-session-id</id></CLIENT></IKE></TUNNEL><name>synthetic</name></NC_RESOURCE><IPSEC_RESOURCE/></RESOURCE_LIST></INTERGRATION_INFO></ROOT>"
    return try PortalXMLStructuralParser().parse(
      consuming: SecureBytes(copying: Array(xml.utf8))
    )
  }
}

private final class ConcurrentSnapshotBorrowState: @unchecked Sendable {
  enum Event: Equatable {
    case borrowEntered
    case eraseStarted
    case borrowLeaving
    case eraseFinished
  }

  private let lock = NSLock()
  private var recorded: [Event] = []

  func append(_ event: Event) {
    lock.withLock { recorded.append(event) }
  }

  func contains(_ event: Event) -> Bool {
    lock.withLock { recorded.contains(event) }
  }

  var events: [Event] { lock.withLock { recorded } }
}

private func waitUntil(
  _ predicate: () -> Bool
) async -> Bool {
  for _ in 0..<10_000 {
    if predicate() { return true }
    await Task.yield()
  }
  return predicate()
}
