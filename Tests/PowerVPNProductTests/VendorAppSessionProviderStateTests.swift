import Darwin
import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppSessionProviderStateTests {
  @Test func availabilityAndReadinessRejectAndEraseStaleMaterial() throws {
    let availabilityMaterial = try vendorAppMaterial()
    let availabilityState = VendorAppSessionProviderState(
      cursor: try syntheticCursor(inode: 61),
      material: availabilityMaterial,
      sourceIsCurrent: { _ in false }
    )
    #expect(!availabilityState.isAvailable)
    #expect(availabilityMaterial.isErased)

    let readinessMaterial = try vendorAppMaterial()
    let readinessState = VendorAppSessionProviderState(
      cursor: try syntheticCursor(inode: 62),
      material: readinessMaterial,
      sourceIsCurrent: { _ in false }
    )
    #expect(readinessState.readinessCandidate() == nil)
    #expect(readinessMaterial.isErased)
  }

  @Test func availabilityRequiresHandoffProofAtBothReadinessChecks() throws {
    let legacyMaterial = try vendorAppMaterial()
    let legacy = VendorAppSessionProviderState(
      cursor: try syntheticCursor(inode: 71),
      material: legacyMaterial,
      handoffProofIsCurrent: { cursor, _ in cursor.handoffProof != nil }
    )
    #expect(!legacy.isAvailable)
    #expect(legacyMaterial.isErased)

    let armed = try syntheticCursor(inode: 72)
    let proven = try armed.proving(syntheticProof(for: armed))
    let provenMaterial = try vendorAppMaterial()
    let current = VendorAppSessionProviderState(
      cursor: proven,
      material: provenMaterial,
      handoffProofIsCurrent: { cursor, _ in cursor.handoffProof != nil }
    )
    #expect(current.isAvailable)
    #expect(current.readinessCandidate()?.summary.displayName == "login21")
    #expect(!provenMaterial.isErased)
  }

  @Test func resourceAndTargetSelectionFailuresDoNotConsumeProof() async throws {
    let cases: [(String, ProductM2SSHTarget, ProductM2AuthorizedResourceSelectionError)] = [
      ("missing", .thu21, .resourceNotFound),
      ("login21", .thu52, .selectedRouteCoverageRejected),
    ]
    for (displayName, target, expected) in cases {
      let trace = ProductM2TestTrace()
      let (lease, material) = try await acquiredLease(trace: trace)

      let error = await selectionError {
        _ = try await lease.selectUnique(
          displayName: displayName,
          requiredTargetIPv4: target.requiredTargetIPv4
        )
      }

      #expect(error == expected)
      #expect(trace.count("consume_cursor") == 0)
      #expect(
        (await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)).outcome
          == .accepted)
      #expect(trace.count("consume_cursor") == 0)
      #expect(material.isErased)
    }
  }

  @Test func proofConsumptionLinearizesOnceImmediatelyBeforeStartSubmission() async throws {
    let trace = ProductM2TestTrace()
    let (lease, material) = try await acquiredLease(trace: trace)
    let selection = try await lease.selectUnique(
      displayName: "login21",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )
    let copy = selection

    let pending = try await selection.beginStart(
      control: productM2TestControl(trace: trace, plan: .acknowledged),
      deadline: m2TestBudget().work,
      peerGenerationValidator: { true }
    )
    _ = await pending.result()

    let events = trace.events
    let sourceCheck = try #require(events.lastIndex(of: "source_seal_current"))
    let consumption = try #require(events.firstIndex(of: "consume_cursor"))
    let submission = try #require(events.firstIndex(of: "begin_start"))
    #expect(trace.count("consume_cursor") == 1)
    #expect(sourceCheck < consumption)
    #expect(consumption + 1 == submission)
    let replay = await selectionError {
      _ = try await copy.beginStart(
        control: productM2TestControl(trace: trace, plan: .acknowledged),
        deadline: m2TestBudget().work,
        peerGenerationValidator: { true }
      )
    }
    #expect(replay == .startAlreadyIssued)
    #expect(trace.count("consume_cursor") == 1)
    _ = await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)
    #expect(trace.count("consume_cursor") == 1)
    #expect(material.isErased)
  }

  @Test func cancellationRaisedByCursorConsumeCannotSkipSubmittedStart() async throws {
    let trace = ProductM2TestTrace()
    let (lease, material) = try await acquiredLease(
      trace: trace,
      cancelDuringConsume: true
    )
    let selection = try await lease.selectUnique(
      displayName: "login21",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )

    let result = try await Task { () throws -> ProductM2StartResult in
      let pending = try await selection.beginStart(
        control: productM2TestControl(trace: trace, plan: .acknowledged),
        deadline: m2TestBudget().work,
        peerGenerationValidator: { true }
      )
      return await pending.result()
    }.value

    #expect(trace.count("consume_cursor") == 1)
    #expect(trace.count("begin_start") == 1)
    #expect(result.receipt.requestSent)
    let controlLease = try #require(result.lease)
    let stop = await controlLease.stop(timeoutMilliseconds: 500)
    #expect(stop.requestSent)
    #expect(trace.count("stop") == 1)
    _ = await lease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)
    #expect(material.isErased)
  }

  @Test func cancellationAndChangedSourceSealBeforeStartPreserveProof() async throws {
    let cancellationTrace = ProductM2TestTrace()
    let (cancelLease, cancelMaterial) = try await acquiredLease(trace: cancellationTrace)
    let cancelSelection = try await cancelLease.selectUnique(
      displayName: "login21",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )
    let cancelled = await Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return await selectionError {
        _ = try await cancelSelection.beginStart(
          control: productM2TestControl(trace: cancellationTrace, plan: .acknowledged),
          deadline: m2TestBudget().work,
          peerGenerationValidator: { true }
        )
      }
    }.value
    #expect(cancelled == .workAborted)
    #expect(cancellationTrace.count("consume_cursor") == 0)
    #expect(cancellationTrace.count("begin_start") == 0)
    _ = await cancelLease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)
    #expect(cancelMaterial.isErased)

    let sourceState = VendorAppProviderSourceState()
    let sourceTrace = ProductM2TestTrace()
    let (sourceLease, sourceMaterial) = try await acquiredLease(
      trace: sourceTrace,
      sourceState: sourceState
    )
    let sourceSelection = try await sourceLease.selectUnique(
      displayName: "login21",
      requiredTargetIPv4: ProductM2SSHTarget.thu21.requiredTargetIPv4
    )
    sourceState.setCurrent(false)
    let stale = await selectionError {
      _ = try await sourceSelection.beginStart(
        control: productM2TestControl(trace: sourceTrace, plan: .acknowledged),
        deadline: m2TestBudget().work,
        peerGenerationValidator: { true }
      )
    }
    #expect(stale == .startSnapshotRejected)
    #expect(sourceTrace.count("consume_cursor") == 0)
    #expect(sourceTrace.count("begin_start") == 0)
    _ = await sourceLease.closeAndErase(deadline: m2TestBudget().authorizationCleanup)
    #expect(sourceMaterial.isErased)
  }

  private func acquiredLease(
    trace: ProductM2TestTrace,
    sourceState: VendorAppProviderSourceState = VendorAppProviderSourceState(),
    cancelDuringConsume: Bool = false
  ) async throws -> (ProductM2AuthorizedResourceLease, VendorAppSessionSnapshotMaterial) {
    let armed = try syntheticCursor(inode: 101)
    let proven = try armed.proving(syntheticProof(for: armed))
    let material = try vendorAppMaterial(sourceCurrent: {
      trace.record("source_seal_current")
      return sourceState.isCurrent
    })
    let state = VendorAppSessionProviderState(
      cursor: proven,
      material: material,
      handoffProofIsCurrent: { _, _ in
        trace.record("handoff_proof_current")
        return true
      },
      consumeCursor: { cursor in
        #expect(cursor == proven)
        trace.record("consume_cursor")
        if cancelDuringConsume { withUnsafeCurrentTask { $0?.cancel() } }
      }
    )
    let provider = VendorAppSessionProvider(state: state)
    switch await provider.beginAcquire(budget: m2TestBudget().authorization).result() {
    case .acquired(let source, let lease, let contacted):
      #expect(source == .vendorOnce)
      #expect(!contacted)
      #expect(trace.count("consume_cursor") == 0)
      return (lease, material)
    case .rejected:
      throw VendorAppSessionSnapshotError.incomplete
    }
  }

  private func syntheticCursor(inode: UInt64) throws -> VendorAppOnboardingCursor {
    let timestamp = try VendorAppCursorTimestamp(seconds: 1_723_000_000, nanoseconds: 123)
    return VendorAppOnboardingCursor(
      schema: VendorAppOnboardingCursor.schemaVersion,
      device: 7,
      inode: inode,
      size: 1_024,
      ownerUID: 0,
      mode: UInt32(S_IFREG | S_IRUSR | S_IWUSR),
      modificationTime: timestamp,
      changeTime: timestamp,
      capturedAt: timestamp
    )
  }

  private func syntheticProof(
    for cursor: VendorAppOnboardingCursor
  ) throws -> VendorAppNonLogoutHandoffProof {
    VendorAppNonLogoutHandoffProof(
      cleanup: VendorAppNonLogoutHandoffCleanupProof(
        complete: true,
        defaultRouteRestored: true,
        dnsRestored: true,
        interfacesRestored: true,
        utunRestored: true,
        persistentRoutesRestored: true,
        surgeStateRestored: true,
        vendorProcessesAbsent: true,
        helperInactive: true,
        structuralRouteTablesEqual: true
      ),
      finalSourceSeal: VendorAppSessionSourceSeal(
        device: cursor.device,
        inode: cursor.inode,
        size: Int64(cursor.size + 512),
        ownerUID: cursor.ownerUID,
        mode: cursor.mode,
        modificationSeconds: cursor.modificationTime.seconds + 1,
        modificationNanoseconds: 0,
        changeSeconds: cursor.changeTime.seconds + 1,
        changeNanoseconds: 0
      ),
      finalHelperRuns: 21,
      createdAt: try VendorAppCursorTimestamp(
        seconds: cursor.capturedAt.seconds + 1,
        nanoseconds: 0
      )
    )
  }
}

private final class VendorAppProviderSourceState: @unchecked Sendable {
  private let lock = NSLock()
  private var current = true

  var isCurrent: Bool { lock.withLock { current } }
  func setCurrent(_ value: Bool) { lock.withLock { current = value } }
}
