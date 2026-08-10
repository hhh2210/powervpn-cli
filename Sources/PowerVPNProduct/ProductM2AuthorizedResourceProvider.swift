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

}

package enum ProductM2AuthorizedResourceAcquisition: Sendable {
  case acquired(
    source: ProductM2AuthorizationSource,
    lease: ProductM2AuthorizedResourceLease,
    serverContactRequested: Bool
  )
  case rejected(
    source: ProductM2AuthorizationSource,
    failure: ProductM2AuthorizationFailure,
    cleanup: ProductM2AuthorizationCloseReceipt
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
      cleanup: ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: true,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    )
  }
}
