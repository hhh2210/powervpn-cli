import Foundation
import PowerVPNCore

@testable import PowerVPNPortal
@testable import PowerVPNProduct

func availability(
  of field: VendorCharonStartField,
  in candidate: ProductResourceCandidate
) -> VendorCharonStartFieldAvailability? {
  candidate.fieldReports.first { $0.field == field }?.availability
}

func sources(
  of field: VendorCharonStartField,
  in candidate: ProductResourceCandidate
) -> [VendorCharonStartMaterialSource]? {
  candidate.fieldReports.first { $0.field == field }?.sources
}

func resourceXML(displayName: String, sessionID: String) -> String {
  """
  <ROOT><INTERGRATION_INFO><VERSION major="2"/><RESOURCE_LIST><NC_RESOURCE>
    <TUNNEL tunnel-name="\(displayName)" status="1"><IKE><CLIENT id="\(sessionID)"/></IKE></TUNNEL>
  </NC_RESOURCE></RESOURCE_LIST></INTERGRATION_INFO></ROOT>
  """
}

final class AuthenticatedSnapshotFixture {
  let snapshot: AuthenticatedPortalSnapshot
  private let request: PortalHTTPRequest
  let factory: PortalRequestFactory

  init(
    snapshot: AuthenticatedPortalSnapshot,
    request: PortalHTTPRequest,
    factory: PortalRequestFactory
  ) {
    self.snapshot = snapshot
    self.request = request
    self.factory = factory
  }

  func erase() {
    snapshot.erase()
    request.erase()
    factory.eraseSession()
  }
}

func authenticatedSnapshot(
  cookie: String = "cookie-session-material",
  resourceXML: String
) throws -> AuthenticatedSnapshotFixture {
  let profile = InstalledPortalProfile(
    origin: URL(string: "https://166.111.143.19:4443")!,
    portalVersion: "2.0",
    selectionSemantics: .latestPrimaryKeyFallback,
    vendorLanguageIndex: 0
  )
  let factory = try PortalRequestFactory(
    profile: profile,
    operatingSystemVersion: "product-mapper-test"
  )
  let passwordResponse = PortalHTTPResponse(
    statusCode: 200,
    body: try SecureBytes(copying: Array("<ROOT/>".utf8)),
    setCookieHeader: try SecureBytes(
      copying: Array("VSG_SESSIONID=\(cookie); Path=/; Secure".utf8)
    ),
    setCookieProjection: .provenLastFieldWins(fieldCount: 1)
  )
  defer { passwordResponse.erase() }
  try factory.acceptPasswordSession(
    from: passwordResponse,
    passwordURL: URL(
      string: "https://166.111.143.19:4443/vpn/user/auth/password"
    )!
  )
  let request = try factory.makeResourceRequest()
  do {
    let document = try PortalXMLStructuralParser().parse(
      consuming: SecureBytes(copying: Array(resourceXML.utf8))
    )
    let snapshot = try factory.mintAuthenticatedSnapshot(
      resourceRequest: request,
      resourceDocument: document
    )
    return AuthenticatedSnapshotFixture(
      snapshot: snapshot,
      request: request,
      factory: factory
    )
  } catch {
    request.erase()
    factory.eraseSession()
    throw error
  }
}

struct MapperProductObservation: ProductReadinessObserving {
  func observe() -> ProductReadinessObservation {
    ProductReadinessObservation(
      installedVersion: "3.2.1",
      installedBuild: "24572",
      installedArchitectures: ["x86_64"],
      officialGUIRunning: false,
      helperAvailable: true,
      generation: VendorHelperGenerationSnapshot(
        launchdObserved: true,
        running: false,
        inactiveConfirmed: true,
        activeCount: 0,
        pid: nil,
        runs: 19
      ),
      directXPCStatus: .notProbed,
      directXPCPreflightSafe: true,
      profileSource: .operatorApprovedFixedOrigin,
      resourceSource: .unavailable,
      resourceCandidates: []
    )
  }
}
