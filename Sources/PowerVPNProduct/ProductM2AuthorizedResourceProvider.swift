import Foundation

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
  case timedOut = "timed_out"
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
  func beginAcquire(
    budget: ProductM2AuthorizationBudget
  ) -> ProductM2AuthorizationAttempt
}

package struct ProductM2AuthorizationAttempt: Sendable {
  private let state: ProductM2AuthorizationAttemptState

  package init(
    source: ProductM2AuthorizationSource,
    operation: @escaping @Sendable () async -> ProductM2AuthorizedResourceAcquisition,
    cancel: @escaping @Sendable () -> Void
  ) {
    state = ProductM2AuthorizationAttemptState(
      source: source,
      operation: operation,
      cancel: cancel
    )
  }

  package func result() async -> ProductM2AuthorizedResourceAcquisition {
    switch state.beginResult() {
    case .operation(let operation):
      let result = await operation()
      state.complete()
      return result
    case .cancelled:
      return state.cancelledResult
    case .closed:
      return state.closedResult
    }
  }

  package func cancel() {
    state.cancel()
  }
}

package struct ProductM2UnavailableVendorOnceProvider:
  ProductM2AuthorizedResourceProviding
{
  package let source = ProductM2AuthorizationSource.vendorOnce
  package let availabilityFailure: ProductM2AuthorizationFailure? = .providerUnavailable

  package init() {}

  package func beginAcquire(
    budget: ProductM2AuthorizationBudget
  ) -> ProductM2AuthorizationAttempt {
    ProductM2AuthorizationAttempt(
      source: .vendorOnce,
      operation: {
        .rejected(
          source: .vendorOnce,
          failure: budget.work.hasRemaining ? .providerUnavailable : .timedOut,
          cleanup: ProductM2AuthorizationCloseReceipt(
            outcome: .notRequired,
            ownedMaterialErased: true,
            sourceCloseRequested: false,
            serverContactRequested: false
          )
        )
      },
      cancel: {}
    )
  }
}

private enum ProductM2AuthorizationAttemptStart {
  case operation(@Sendable () async -> ProductM2AuthorizedResourceAcquisition)
  case cancelled
  case closed
}

private final class ProductM2AuthorizationAttemptState: @unchecked Sendable {
  private let lock = NSLock()
  private let source: ProductM2AuthorizationSource
  private var operation: (@Sendable () async -> ProductM2AuthorizedResourceAcquisition)?
  private var cancelOperation: (@Sendable () -> Void)?
  private var resultStarted = false
  private var cancelledBeforeResult = false

  init(
    source: ProductM2AuthorizationSource,
    operation: @escaping @Sendable () async -> ProductM2AuthorizedResourceAcquisition,
    cancel: @escaping @Sendable () -> Void
  ) {
    self.source = source
    self.operation = operation
    cancelOperation = cancel
  }

  func beginResult() -> ProductM2AuthorizationAttemptStart {
    lock.withLock {
      guard !resultStarted else { return .closed }
      resultStarted = true
      guard !cancelledBeforeResult else { return .cancelled }
      guard let operation else { return .closed }
      self.operation = nil
      return .operation(operation)
    }
  }

  func complete() {
    lock.withLock { cancelOperation = nil }
  }

  func cancel() {
    let cancellation: (@Sendable () -> Void)? = lock.withLock {
      guard let pending = cancelOperation else { return nil }
      cancelOperation = nil
      if !resultStarted {
        cancelledBeforeResult = true
        operation = nil
      }
      return pending
    }
    cancellation?()
  }

  var cancelledResult: ProductM2AuthorizedResourceAcquisition {
    .rejected(
      source: source,
      failure: .cancelled,
      cleanup: ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: true,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    )
  }

  var closedResult: ProductM2AuthorizedResourceAcquisition {
    .rejected(
      source: source,
      failure: .internalFailure,
      cleanup: ProductM2AuthorizationCloseReceipt(
        outcome: .notRequired,
        ownedMaterialErased: false,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    )
  }
}
