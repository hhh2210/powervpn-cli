public enum PortalLoginStatus: String, Encodable, Equatable, Sendable {
  case accepted
  case configurationRejected = "configuration_rejected"
  case credentialInputRejected = "credential_input_rejected"
  case transportRejected = "transport_rejected"
  case tlsRejected = "tls_rejected"
  case redirectRejected = "redirect_rejected"
  case loginRejected = "login_rejected"
  case challengeRequired = "challenge_required"
  case loginResponseRejected = "login_response_rejected"
  case sessionRejected = "session_rejected"
  case resourceListRejected = "resource_list_rejected"
  case authenticatedSnapshotRejected = "authenticated_snapshot_rejected"
  case logoutRejected = "logout_rejected"
  case cancelled
  case internalFailure = "internal_failure"
}

public struct PortalOperationEvidence: Encodable, Equatable, Sendable {
  public let loginRequested: Bool
  public let loginAccepted: Bool
  public let sessionCheckRequested: Bool
  public let sessionCheckAccepted: Bool
  public let resourceListRequested: Bool
  public let resourceListAccepted: Bool
  public let logoutRequested: Bool
  public let logoutAccepted: Bool

}

public struct PortalOwnedMaterialEvidence: Encodable, Equatable, Sendable {
  public let credentialsErased: Bool
  public let requestBodiesErased: Bool
  public let responseBodiesErased: Bool
  public let sessionMaterialErased: Bool

}

public struct PortalSafetyEvidence: Encodable, Equatable, Sendable {
  public let credentialSource: String
  public let endpointSource: String
  public let systemTrustRequired: Bool
  public let redirectsAllowed: Bool
  public let credentialInArguments: Bool
  public let credentialInEnvironment: Bool
  public let credentialWrittenToFile: Bool
  public let endpointValueRetainedInEvidence: Bool
  public let platformSerialValueRetainedInEvidence: Bool
  public let rawRequestRetainedInEvidence: Bool
  public let rawResponseRetainedInEvidence: Bool
  public let sessionValueRetainedInEvidence: Bool
  public let resourceValueRetainedInEvidence: Bool
  public let portalHTTPSAllowed: Bool
  public let helperMutationRequested: Bool
  public let xpcUsed: Bool
  public let viciUsed: Bool
  public let ikeTrafficRequested: Bool
  public let appOwnedSecureBuffersErasureObserved: Bool
  public let swiftAndFoundationBridgeCopiesErasureClaimed: Bool

  static let r2 = PortalSafetyEvidence(
    credentialSource: "controlling_tty_no_echo",
    endpointSource: "sealed_installed_configuration",
    systemTrustRequired: true,
    redirectsAllowed: false,
    credentialInArguments: false,
    credentialInEnvironment: false,
    credentialWrittenToFile: false,
    endpointValueRetainedInEvidence: false,
    platformSerialValueRetainedInEvidence: false,
    rawRequestRetainedInEvidence: false,
    rawResponseRetainedInEvidence: false,
    sessionValueRetainedInEvidence: false,
    resourceValueRetainedInEvidence: false,
    portalHTTPSAllowed: true,
    helperMutationRequested: false,
    xpcUsed: false,
    viciUsed: false,
    ikeTrafficRequested: false,
    appOwnedSecureBuffersErasureObserved: true,
    swiftAndFoundationBridgeCopiesErasureClaimed: false
  )
}

public struct PortalLoginReport: Encodable, Equatable, Sendable {
  public let schemaVersion: Int
  public let mode: String
  public let status: PortalLoginStatus
  public let operations: PortalOperationEvidence
  public let ownedMaterial: PortalOwnedMaterialEvidence
  public let safety: PortalSafetyEvidence
  public let transactionAccepted: Bool

  private static func accepts(
    status: PortalLoginStatus,
    operations: PortalOperationEvidence,
    ownedMaterial: PortalOwnedMaterialEvidence,
    safety: PortalSafetyEvidence
  ) -> Bool {
    status == .accepted
      && operations.loginRequested
      && operations.loginAccepted
      && operations.sessionCheckRequested
      && operations.sessionCheckAccepted
      && operations.resourceListRequested
      && operations.resourceListAccepted
      && operations.logoutRequested
      && operations.logoutAccepted
      && ownedMaterial.credentialsErased
      && ownedMaterial.requestBodiesErased
      && ownedMaterial.responseBodiesErased
      && ownedMaterial.sessionMaterialErased
      && safety.systemTrustRequired
      && !safety.redirectsAllowed
      && !safety.credentialInArguments
      && !safety.credentialInEnvironment
      && !safety.credentialWrittenToFile
      && !safety.endpointValueRetainedInEvidence
      && !safety.platformSerialValueRetainedInEvidence
      && !safety.rawRequestRetainedInEvidence
      && !safety.rawResponseRetainedInEvidence
      && !safety.sessionValueRetainedInEvidence
      && !safety.resourceValueRetainedInEvidence
      && safety.portalHTTPSAllowed
      && !safety.helperMutationRequested
      && !safety.xpcUsed
      && !safety.viciUsed
      && !safety.ikeTrafficRequested
      && safety.appOwnedSecureBuffersErasureObserved
      && !safety.swiftAndFoundationBridgeCopiesErasureClaimed
  }

  init(
    status: PortalLoginStatus,
    operations: PortalOperationEvidence,
    ownedMaterial: PortalOwnedMaterialEvidence,
    safety: PortalSafetyEvidence = .r2
  ) {
    schemaVersion = 1
    mode = "r2_username_password_portal_login"
    self.status = status
    self.operations = operations
    self.ownedMaterial = ownedMaterial
    self.safety = safety
    transactionAccepted = Self.accepts(
      status: status,
      operations: operations,
      ownedMaterial: ownedMaterial,
      safety: safety
    )
  }
}
