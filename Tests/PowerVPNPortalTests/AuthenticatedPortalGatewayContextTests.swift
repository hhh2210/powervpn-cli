import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct AuthenticatedPortalGatewayContextTests {
  @Test func sealedLiteralIPv4IsScopedToTheAuthenticatedGeneration() throws {
    let fixture = try gatewayContextFixture()
    defer { fixture.erase() }
    var escaped: AuthenticatedPortalContext?

    let shape = try fixture.snapshot.withPortalContext { context in
      escaped = context
      #expect((context as Any) is any Encodable == false)
      return try context.withVendorGatewayBytes {
        (
          exactSealedGateway: $0.elementsEqual(Array("166.111.143.19".utf8)),
          byteCount: $0.count
        )
      }
    }

    #expect(shape.exactSealedGateway)
    #expect(shape.byteCount == 14)
    #expect(throws: AuthenticatedPortalContextBorrowError.expired) {
      _ = try escaped?.withVendorGatewayBytes(\.count)
    }
  }

  @Test func sessionInvalidationRevokesGatewayBorrowWithoutClaimingErasure() throws {
    let fixture = try gatewayContextFixture()
    defer { fixture.erase() }

    try fixture.snapshot.withPortalContext { context in
      fixture.factory.eraseSession()
      #expect(throws: AuthenticatedPortalContextBorrowError.expired) {
        _ = try context.withVendorGatewayBytes(\.count)
      }
    }

    #expect(!fixture.snapshot.isAccessible)
    #expect(!fixture.snapshot.isErased)
  }

  @Test func snapshotEraseZeroesOwnedGatewayStorage() throws {
    let observation = GatewayZeroObservation()
    let generation = PortalAuthenticationGeneration()
    let gateway = try SecureBytes(
      copying: Array("166.111.143.19".utf8),
      eraseObserver: { observation.record($0) }
    )
    let snapshot = try AuthenticatedPortalSnapshot(
      resourceDocument: try gatewayDocument(),
      authenticationGeneration: generation,
      vendorGateway: gateway
    )

    #expect(gateway.count == 14)
    snapshot.erase()

    #expect(snapshot.isErased)
    #expect(gateway.count == 0)
    #expect(observation.snapshots.count == 1)
    #expect(observation.snapshots[0].count == 14)
    #expect(observation.snapshots[0].allSatisfy { $0 == 0 })
  }

  @Test func snapshotDeinitZeroesOwnedGatewayStorage() throws {
    let observation = GatewayZeroObservation()
    let gateway = try SecureBytes(
      copying: Array("166.111.143.19".utf8),
      eraseObserver: { observation.record($0) }
    )
    var snapshot: AuthenticatedPortalSnapshot? = try AuthenticatedPortalSnapshot(
      resourceDocument: try gatewayDocument(),
      authenticationGeneration: PortalAuthenticationGeneration(),
      vendorGateway: gateway
    )
    weak let weakSnapshot = snapshot

    snapshot = nil

    #expect(weakSnapshot == nil)
    #expect(gateway.count == 0)
    #expect(observation.snapshots.count == 1)
    #expect(observation.snapshots[0].allSatisfy { $0 == 0 })
  }

  @Test func hostnameIPv6AndDifferentLiteralProfilesFailClosed() {
    let origins = [
      "https://portal.example.invalid:4443",
      "https://[2001:db8::1]:4443",
      "https://192.0.2.1:4443",
    ]

    for origin in origins {
      let profile = InstalledPortalProfile(
        origin: URL(string: origin)!,
        portalVersion: "2.0",
        selectionSemantics: .latestPrimaryKeyFallback,
        vendorLanguageIndex: 0
      )
      #expect(throws: PortalRequestFactoryError.invalidProfile) {
        _ = try PortalRequestFactory(
          profile: profile,
          operatingSystemVersion: "gateway-negative-test"
        )
      }
    }
  }
}

private struct GatewayContextFixture {
  let snapshot: AuthenticatedPortalSnapshot
  let request: PortalHTTPRequest
  let factory: PortalRequestFactory

  func erase() {
    snapshot.erase()
    request.erase()
    factory.eraseSession()
  }
}

private func gatewayContextFixture() throws -> GatewayContextFixture {
  let factory = try syntheticRequestFactory()
  let response = PortalHTTPResponse(
    statusCode: 200,
    body: try SecureBytes(copying: Array(acceptedLoginXML.utf8)),
    setCookieHeader: try SecureBytes(
      copying: Array("VSG_SESSIONID=gateway-test; Path=/; Secure".utf8)
    ),
    setCookieProjection: .provenSingleWireHeader
  )
  defer { response.erase() }
  try factory.acceptPasswordSession(
    from: response,
    passwordURL: URL(string: "https://166.111.143.19:4443/vpn/user/auth/password")!
  )
  let request = try factory.makeResourceRequest()
  do {
    return GatewayContextFixture(
      snapshot: try factory.mintAuthenticatedSnapshot(
        resourceRequest: request,
        resourceDocument: try gatewayDocument()
      ),
      request: request,
      factory: factory
    )
  } catch {
    request.erase()
    factory.eraseSession()
    throw error
  }
}

private func gatewayDocument() throws -> PortalXMLDocument {
  let xml =
    "<ROOT><INTERGRATION_INFO><VERSION major=\"2\"/>"
    + "<RESOURCE_LIST/></INTERGRATION_INFO></ROOT>"
  return try PortalXMLStructuralParser().parse(
    consuming: SecureBytes(copying: Array(xml.utf8))
  )
}

private final class GatewayZeroObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [[UInt8]] = []

  var snapshots: [[UInt8]] { lock.withLock { storage } }
  func record(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock { storage.append(Array(bytes)) }
  }
}
