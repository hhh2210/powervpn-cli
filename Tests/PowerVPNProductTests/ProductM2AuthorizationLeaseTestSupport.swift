import Foundation

@testable import PowerVPNPortal
@testable import PowerVPNProduct

func testAuthorizationLease(
  snapshot: AuthenticatedPortalSnapshot,
  state: AuthorizationLeaseTestState,
  closeGate: AuthorizationCloseGate? = nil,
  eraseSucceeds: Bool = true,
  onClose: @escaping @Sendable () -> Void = {}
) -> ProductM2AuthorizedResourceLease {
  ProductM2AuthorizedResourceLease(
    source: .nativePortal,
    catalog: {
      state.recordCatalog()
      return try ProductM2PortalAdapter.catalog(snapshot: snapshot)
    },
    prepare: { handle, target in
      state.recordPrepare()
      return try ProductM2PortalAdapter.prepare(
        snapshot: snapshot,
        handle: handle,
        requiredTargetIPv4: target
      )
    },
    eraseOwnedMaterial: {
      if eraseSucceeds { snapshot.erase() }
      state.recordErase(snapshot.isErased)
      return snapshot.isErased
    },
    close: { _ in
      state.recordClose()
      onClose()
      if let closeGate { await closeGate.block() }
      return closeReceipt(erased: state.erased)
    }
  )
}

func closeReceipt(erased: Bool) -> ProductM2AuthorizationCloseReceipt {
  ProductM2AuthorizationCloseReceipt(
    outcome: .accepted,
    ownedMaterialErased: erased,
    sourceCloseRequested: false,
    serverContactRequested: false
  )
}

func selectionError(
  _ operation: () async throws -> Void
) async -> ProductM2AuthorizedResourceSelectionError? {
  do {
    try await operation()
    return nil
  } catch let error as ProductM2AuthorizedResourceSelectionError {
    return error
  } catch {
    return nil
  }
}

final class AuthorizationLeaseTestState: @unchecked Sendable {
  private let lock = NSLock()
  private var catalogCalls = 0
  private var prepareCalls = 0
  private var eraseCalls = 0
  private var closeCalls = 0
  private var materialErased = false

  func recordCatalog() { lock.withLock { catalogCalls += 1 } }
  func recordPrepare() { lock.withLock { prepareCalls += 1 } }
  func recordClose() { lock.withLock { closeCalls += 1 } }
  func recordErase(_ erased: Bool) {
    lock.withLock {
      eraseCalls += 1
      materialErased = erased
    }
  }

  var catalogCount: Int { lock.withLock { catalogCalls } }
  var prepareCount: Int { lock.withLock { prepareCalls } }
  var eraseCount: Int { lock.withLock { eraseCalls } }
  var closeCount: Int { lock.withLock { closeCalls } }
  var erased: Bool { lock.withLock { materialErased } }
}

actor AuthorizationCloseGate {
  private var entered = false
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseContinuation: CheckedContinuation<Void, Never>?

  func block() async {
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
