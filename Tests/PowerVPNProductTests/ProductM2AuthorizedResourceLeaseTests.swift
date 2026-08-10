import Foundation
import Testing

@testable import PowerVPNPortal
@testable import PowerVPNProduct

@Suite struct ProductM2AuthorizedResourceLeaseTests {
  @Test func catalogIsStableAndSelectionIsSingleShot() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    let lease = testAuthorizationLease(snapshot: fixture.snapshot, state: state)

    let first = try await lease.catalog()
    let second = try await lease.catalog()
    #expect(first == second)
    #expect(state.catalogCount == 1)

    _ = try await lease.selectUnique(
      displayName: "Campus NC",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )
    #expect(state.prepareCount == 1)
    let replay = await selectionError {
      _ = try await lease.selectUnique(
        displayName: "Campus NC",
        requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
      )
    }
    #expect(replay == .selectionAlreadyIssued)
    #expect(state.prepareCount == 1)
    #expect((await lease.closeAndErase()).outcome == .accepted)
  }

  @Test func failedPrepareConsumesTheOnlySelectionAttempt() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let snapshot = fixture.snapshot
    let state = AuthorizationLeaseTestState()
    let lease = ProductM2AuthorizedResourceLease(
      source: .vendorOnce,
      catalog: {
        state.recordCatalog()
        return try ProductM2PortalAdapter.catalog(snapshot: snapshot)
      },
      prepare: { _, _ in
        state.recordPrepare()
        throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
      },
      eraseOwnedMaterial: {
        snapshot.erase()
        state.recordErase(snapshot.isErased)
        return snapshot.isErased
      },
      close: {
        state.recordClose()
        return closeReceipt(erased: state.erased)
      }
    )

    let first = await selectionError {
      _ = try await lease.selectUnique(
        displayName: "Campus NC",
        requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
      )
    }
    let second = await selectionError {
      _ = try await lease.selectUnique(
        displayName: "Campus NC",
        requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
      )
    }
    #expect(first == .startSnapshotRejected)
    #expect(second == .selectionAlreadyIssued)
    #expect(state.prepareCount == 1)
    _ = await lease.closeAndErase()
  }

  @Test func copiedSelectionCannotReplayStart() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    let trace = ProductM2TestTrace()
    let lease = testAuthorizationLease(snapshot: fixture.snapshot, state: state)
    let selection = try await lease.selectUnique(
      displayName: "Campus NC",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )
    let copy = selection
    let pending = try await selection.beginStart(
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      peerGenerationValidator: { true }
    )
    _ = await pending.result()

    let replay = await selectionError {
      _ = try await copy.beginStart(
        control: productM2TestControl(trace: trace, plan: .acknowledged),
        peerGenerationValidator: { true }
      )
    }
    #expect(replay == .startAlreadyIssued)
    #expect(trace.count("begin_start") == 1)
    _ = await lease.closeAndErase()
  }

  @Test func closeMarksClosingAndErasesBeforeAwaitingSource() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    let gate = AuthorizationCloseGate()
    let trace = ProductM2TestTrace()
    let lease = testAuthorizationLease(
      snapshot: fixture.snapshot,
      state: state,
      closeGate: gate
    )
    let selection = try await lease.selectUnique(
      displayName: "Campus NC",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )

    let closing = Task { await lease.closeAndErase() }
    await gate.waitUntilEntered()
    #expect(state.eraseCount == 1)
    #expect(state.erased)
    let beginAfterClose = await selectionError {
      _ = try await selection.beginStart(
        control: productM2TestControl(trace: trace, plan: .acknowledged),
        peerGenerationValidator: { true }
      )
    }
    #expect(beginAfterClose == .leaseClosed)
    #expect(trace.count("begin_start") == 0)
    await gate.release()
    #expect((await closing.value).outcome == .accepted)
  }

  @Test func concurrentCloseErasesAndCallsSourceExactlyOnce() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    let lease = testAuthorizationLease(snapshot: fixture.snapshot, state: state)

    let receipts = await withTaskGroup(
      of: ProductM2AuthorizationCloseReceipt.self,
      returning: [ProductM2AuthorizationCloseReceipt].self
    ) { group in
      for _ in 0..<8 { group.addTask { await lease.closeAndErase() } }
      var values: [ProductM2AuthorizationCloseReceipt] = []
      for await value in group { values.append(value) }
      return values
    }

    #expect(receipts.count { $0.outcome == .accepted } == 1)
    #expect(receipts.count { $0.outcome == .alreadyClosed } == 7)
    #expect(state.eraseCount == 1)
    #expect(state.closeCount == 1)
  }

  @Test func acceptedCloseIsDowngradedWhenEraseFails() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    let lease = testAuthorizationLease(
      snapshot: fixture.snapshot,
      state: state,
      eraseSucceeds: false
    )

    let receipt = await lease.closeAndErase()
    #expect(receipt.outcome == .rejected)
    #expect(!receipt.ownedMaterialErased)
    #expect(state.eraseCount == 1)
  }

  @Test func abandonedLeaseUsesSynchronousEraseFallback() async throws {
    let fixture = try authenticatedSnapshot(resourceXML: m2ResourceXML(["Campus NC"]))
    defer { fixture.erase() }
    let state = AuthorizationLeaseTestState()
    var lease: ProductM2AuthorizedResourceLease? = testAuthorizationLease(
      snapshot: fixture.snapshot,
      state: state
    )
    #expect(lease != nil)

    lease = nil
    #expect(state.eraseCount == 1)
    #expect(state.closeCount == 0)
    #expect(fixture.snapshot.isErased)
  }
}

private func testAuthorizationLease(
  snapshot: AuthenticatedPortalSnapshot,
  state: AuthorizationLeaseTestState,
  closeGate: AuthorizationCloseGate? = nil,
  eraseSucceeds: Bool = true
) -> ProductM2AuthorizedResourceLease {
  ProductM2AuthorizedResourceLease(
    source: .vendorOnce,
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
    close: {
      state.recordClose()
      if let closeGate { await closeGate.block() }
      return closeReceipt(erased: state.erased)
    }
  )
}

private func closeReceipt(erased: Bool) -> ProductM2AuthorizationCloseReceipt {
  ProductM2AuthorizationCloseReceipt(
    outcome: .accepted,
    ownedMaterialErased: erased,
    sourceCloseRequested: false,
    serverContactRequested: false
  )
}

private func selectionError(
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

private final class AuthorizationLeaseTestState: @unchecked Sendable {
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

private actor AuthorizationCloseGate {
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
