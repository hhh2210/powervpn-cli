import PowerVPNPortal

public enum ProductM2AuthorizationSource: String, Encodable, Equatable, Sendable {
  case vendorOnce = "vendor_once"
  case nativePortal = "native_portal"
}

public enum ProductM2AuthorizationFailure: String, Encodable, Equatable, Sendable {
  case providerUnavailable = "provider_unavailable"
  case sourceMismatch = "source_mismatch"
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

  init(_ status: PortalLoginStatus) {
    switch status {
    case .accepted: self = .accepted
    case .configurationRejected: self = .configurationRejected
    case .credentialInputRejected: self = .credentialInputRejected
    case .transportRejected: self = .transportRejected
    case .tlsRejected: self = .tlsRejected
    case .redirectRejected: self = .redirectRejected
    case .loginRejected: self = .loginRejected
    case .challengeRequired: self = .challengeRequired
    case .loginResponseRejected: self = .loginResponseRejected
    case .sessionRejected: self = .sessionRejected
    case .resourceListRejected: self = .resourceListRejected
    case .authenticatedSnapshotRejected: self = .authenticatedSnapshotRejected
    case .logoutRejected: self = .logoutRejected
    case .cancelled: self = .cancelled
    case .internalFailure: self = .internalFailure
    }
  }
}

package enum ProductM2AuthorizedResourceAcquisition: Sendable {
  case acquired(
    source: ProductM2AuthorizationSource,
    lease: any ProductM2PortalLeasing
  )
  case rejected(
    source: ProductM2AuthorizationSource,
    failure: ProductM2AuthorizationFailure,
    serverContactRequested: Bool
  )
}

package protocol ProductM2AuthorizedResourceProviding: Sendable {
  var source: ProductM2AuthorizationSource { get }
  var availabilityFailure: ProductM2AuthorizationFailure? { get }
  func acquire() async -> ProductM2AuthorizedResourceAcquisition
}

package struct ProductM2UnavailableVendorOnceProvider:
  ProductM2AuthorizedResourceProviding
{
  package let source = ProductM2AuthorizationSource.vendorOnce
  package let availabilityFailure: ProductM2AuthorizationFailure? = .providerUnavailable

  package init() {}

  package func acquire() async -> ProductM2AuthorizedResourceAcquisition {
    .rejected(
      source: source,
      failure: .providerUnavailable,
      serverContactRequested: false
    )
  }
}

package struct ProductM2PortalAdapter: ProductM2AuthorizedResourceProviding {
  package typealias AcquirePortal = @Sendable () async -> PortalSnapshotAcquisitionResult

  package let source = ProductM2AuthorizationSource.nativePortal
  package let availabilityFailure: ProductM2AuthorizationFailure? = nil
  private let acquirePortal: AcquirePortal

  package init(
    acquirePortal: @escaping AcquirePortal = PortalLoginRuntime.acquireCurrentMachine
  ) {
    self.acquirePortal = acquirePortal
  }

  package func acquire() async -> ProductM2AuthorizedResourceAcquisition {
    switch await acquirePortal() {
    case .acquired(let lease):
      return .acquired(source: source, lease: lease)
    case .rejected(let report):
      let operations = report.operations
      return .rejected(
        source: source,
        failure: ProductM2AuthorizationFailure(report.status),
        serverContactRequested: operations.loginRequested
          || operations.sessionCheckRequested
          || operations.resourceListRequested
          || operations.logoutRequested
      )
    }
  }

  package static func acquireCurrentMachine() async -> ProductM2AuthorizedResourceAcquisition {
    await Self().acquire()
  }
}
