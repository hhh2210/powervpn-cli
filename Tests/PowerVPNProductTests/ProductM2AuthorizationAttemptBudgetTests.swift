import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AuthorizationAttemptBudgetTests {
  @Test func cancelBeforeResultIsSynchronousIdempotentAndDoesNotReplayResult() async {
    let observation = ProductM2AuthorizationAttemptObservation()
    let attempt = ProductM2AuthorizationAttempt(
      source: .nativePortal,
      operation: {
        observation.recordResult()
        return rejectedAuthorization(.cancelled)
      },
      cancel: observation.recordCancel
    )

    attempt.cancel()
    attempt.cancel()
    let first = await attempt.result()
    let second = await attempt.result()

    #expect(observation.cancelCount == 1)
    #expect(observation.resultCount == 0)
    expectCancelledBeforeResult(first, source: .nativePortal)
    expectFailure(second, .internalFailure)
  }

  @Test func resultIsOneShotAndCompletionClearsTheCancelAction() async {
    let observation = ProductM2AuthorizationAttemptObservation()
    let attempt = ProductM2AuthorizationAttempt(
      source: .nativePortal,
      operation: {
        observation.recordResult()
        return rejectedAuthorization(.providerUnavailable)
      },
      cancel: observation.recordCancel
    )

    let first = await attempt.result()
    let second = await attempt.result()
    attempt.cancel()

    #expect(observation.resultCount == 1)
    #expect(observation.cancelCount == 0)
    expectFailure(first, .providerUnavailable)
    expectFailure(second, .internalFailure)
  }

  @Test func cancellationBetweenTaskCreationAndInstallNeverStartsPortal() async {
    let observation = ProductM2AuthorizationAttemptObservation()
    let gap = ProductM2PortalInstallGap()
    let provider = ProductM2PortalAdapter(
      acquirePortal: { _ in
        observation.recordResult()
        return .rejected(cancelledPortalReport())
      },
      beforeTaskInstall: { await gap.pause() }
    )
    let attempt = provider.beginAcquire(budget: m2TestBudget().authorization)
    let resultTask = Task { await attempt.result() }

    await gap.waitUntilEntered()
    attempt.cancel()
    await gap.release()
    let result = await resultTask.value

    #expect(observation.resultCount == 0)
    expectCancelledBeforeResult(result, source: .nativePortal)
  }

  @Test func portalCloseSkipsFixedLogoutUnlessFullTwentySecondsRemain() async throws {
    let short = try await closePortalLease(at: 74_001)
    #expect(short.receipt.outcome == .timedOut)
    #expect(short.receipt.ownedMaterialErased)
    #expect(!short.receipt.sourceCloseRequested)
    #expect(short.transportRequests == 0)

    let full = try await closePortalLease(at: 74_000)
    #expect(full.receipt.outcome == .accepted)
    #expect(full.receipt.ownedMaterialErased)
    #expect(full.receipt.sourceCloseRequested)
    #expect(full.transportRequests == 1)
  }

  @Test func portalLogoutAcceptanceFlowsThroughProductCloseOutcome() async throws {
    for (statusCode, expected) in [
      (204, ProductM2AuthorizationCloseOutcome.accepted),
      (205, .rejected),
    ] {
      let result = try await closePortalLease(
        at: 74_000,
        logoutStatusCode: statusCode
      )
      #expect(result.receipt.outcome == expected)
      #expect(result.receipt.ownedMaterialErased)
      #expect(result.receipt.sourceCloseRequested)
      #expect(result.receipt.serverContactRequested)
      #expect(result.transportRequests == 1)
    }

    let transportFailure = try await closePortalLease(
      at: 74_000,
      logoutTransportError: .unavailable
    )
    #expect(transportFailure.receipt.outcome == .accepted)
    #expect(transportFailure.receipt.ownedMaterialErased)
    #expect(transportFailure.receipt.sourceCloseRequested)
    #expect(transportFailure.receipt.serverContactRequested)
    #expect(transportFailure.transportRequests == 1)
  }

  private func closePortalLease(
    at milliseconds: UInt64,
    logoutStatusCode: Int = 200,
    logoutTransportError: PortalTransportError? = nil
  ) async throws -> (
    receipt: ProductM2AuthorizationCloseReceipt,
    transportRequests: Int
  ) {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let transport = ProductM2PortalTransportSpy(
      statusCode: logoutStatusCode,
      error: logoutTransportError
    )
    let portalLease = AuthenticatedPortalLease(
      snapshot: fixture.snapshot,
      factory: try productM2PortalRequestFactory(),
      transport: transport,
      logoutBounder: ProductM2ImmediatePortalLogoutBounder()
    )
    let provider = ProductM2PortalAdapter { _ in .acquired(portalLease) }
    let acquisition = await provider.beginAcquire(
      budget: m2TestBudget().authorization
    ).result()
    let lease: ProductM2AuthorizedResourceLease
    switch acquisition {
    case .acquired(_, let acquired, _):
      lease = acquired
    case .rejected:
      Issue.record("synthetic Portal lease was unexpectedly rejected")
      return (
        ProductM2AuthorizationCloseReceipt(
          outcome: .rejected,
          ownedMaterialErased: false,
          sourceCloseRequested: false,
          serverContactRequested: false
        ),
        transport.requestCount
      )
    }

    let clock = ProductM2ManualClock()
    let budget = ProductM2AbsoluteBudget.start(clock: clock.clock)
    clock.set(milliseconds: milliseconds)
    let receipt = await lease.closeAndErase(deadline: budget.authorizationCleanup)
    return (receipt, transport.requestCount)
  }
}

private func cancelledPortalReport() -> PortalLoginReport {
  PortalLoginReport(
    status: .cancelled,
    operations: PortalOperationEvidence(
      loginRequested: false,
      loginAccepted: false,
      sessionCheckRequested: false,
      sessionCheckAccepted: false,
      resourceListRequested: false,
      resourceListAccepted: false,
      logoutRequested: false,
      logoutAccepted: false
    ),
    ownedMaterial: PortalOwnedMaterialEvidence(
      credentialsErased: true,
      requestBodiesErased: true,
      responseBodiesErased: true,
      sessionMaterialErased: true
    )
  )
}

private func expectCancelledBeforeResult(
  _ result: ProductM2AuthorizedResourceAcquisition,
  source expectedSource: ProductM2AuthorizationSource
) {
  switch result {
  case .rejected(let source, let failure, let cleanup):
    #expect(source == expectedSource)
    #expect(failure == .cancelled)
    #expect(cleanup.outcome == .notRequired)
    #expect(cleanup.ownedMaterialErased)
    #expect(!cleanup.sourceCloseRequested)
    #expect(!cleanup.serverContactRequested)
  case .acquired:
    Issue.record("cancel-first authorization must not acquire a lease")
  }
}

private func rejectedAuthorization(
  _ failure: ProductM2AuthorizationFailure
) -> ProductM2AuthorizedResourceAcquisition {
  .rejected(
    source: .nativePortal,
    failure: failure,
    cleanup: ProductM2AuthorizationCloseReceipt(
      outcome: .notRequired,
      ownedMaterialErased: true,
      sourceCloseRequested: false,
      serverContactRequested: false
    )
  )
}

private func expectFailure(
  _ result: ProductM2AuthorizedResourceAcquisition,
  _ expected: ProductM2AuthorizationFailure
) {
  switch result {
  case .rejected(_, let failure, _):
    #expect(failure == expected)
  case .acquired:
    Issue.record("expected rejected authorization")
  }
}

private final class ProductM2AuthorizationAttemptObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var cancels = 0
  private var results = 0

  func recordCancel() { lock.withLock { cancels += 1 } }
  func recordResult() { lock.withLock { results += 1 } }

  var cancelCount: Int { lock.withLock { cancels } }
  var resultCount: Int { lock.withLock { results } }
}

private actor ProductM2PortalInstallGap {
  private var entered = false
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseContinuation: CheckedContinuation<Void, Never>?

  func pause() async {
    entered = true
    for waiter in enteredWaiters { waiter.resume() }
    enteredWaiters.removeAll()
    await withCheckedContinuation { releaseContinuation = $0 }
  }

  func waitUntilEntered() async {
    guard !entered else { return }
    await withCheckedContinuation { enteredWaiters.append($0) }
  }

  func release() {
    releaseContinuation?.resume()
    releaseContinuation = nil
  }
}

private final class ProductM2PortalTransportSpy: @unchecked Sendable, PortalTransporting {
  private let lock = NSLock()
  private let statusCode: Int
  private let error: PortalTransportError?
  private var requests = 0

  init(statusCode: Int, error: PortalTransportError?) {
    self.statusCode = statusCode
    self.error = error
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    guard request.begin() else { throw PortalTransportError.invalidRequest }
    lock.withLock { requests += 1 }
    request.erase()
    if let error { throw error }
    return PortalHTTPResponse(
      statusCode: statusCode,
      body: try SecureBytes(copying: [])
    )
  }

  func cancel() {}

  var requestCount: Int { lock.withLock { requests } }
}

private struct ProductM2ImmediatePortalLogoutBounder: PortalLogoutBounding {
  func run(_ operation: @escaping @Sendable () async -> Void) async -> Bool {
    await operation()
    return true
  }
}

private func productM2PortalRequestFactory() throws -> PortalRequestFactory {
  try PortalRequestFactory(
    profile: InstalledPortalProfile(
      origin: URL(string: "https://166.111.143.19:4443")!,
      portalVersion: "2.0",
      selectionSemantics: .latestPrimaryKeyFallback,
      vendorLanguageIndex: 0
    ),
    operatingSystemVersion: "product-budget-test"
  )
}
