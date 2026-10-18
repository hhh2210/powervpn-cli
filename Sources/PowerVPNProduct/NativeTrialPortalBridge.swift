import Foundation
import PowerVPNCore
import PowerVPNPortal
@preconcurrency import XPC

package enum NativeTrialPortalBridge {
  package enum Failure: Error {
    case catalog(ProductResourceCatalogFailure)
    case selectionMissing
    case selectionAmbiguous(Int)
    case snapshotIncomplete(VendorCharonStartField?)
    case snapshotRejected
  }

  package static func withVendorStartMessage(
    snapshot: AuthenticatedPortalSnapshot, target: PowerVPNTargetConfiguration,
    _ body: (xpc_object_t) throws -> Void
  ) throws {
    let mapped = AuthenticatedPortalSnapshotMapper.mapClassified(snapshot)
    if let failure = mapped.failure { throw Failure.catalog(failure) }
    let selected = mapped.candidates.filter { $0.summary.displayName == target.resourceDisplayName }
    guard !selected.isEmpty else { throw Failure.selectionMissing }
    guard selected.count == 1 else { throw Failure.selectionAmbiguous(selected.count) }
    try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
      snapshot, handle: selected[0].summary.handle
    ) { start in
      try NativeTrialMaterial.withVendorStartMessage(snapshot: start, target: target.host, body)
    }
  }

  package static func withRequests(
    snapshot: AuthenticatedPortalSnapshot,
    target: PowerVPNTargetConfiguration,
    name: String,
    includePrivateRule: Bool = false,
    proposalNumber: UInt8 = 0,
    observeGateway: ((String) throws -> Void)? = nil,
    diagnosticSink: ((Data) -> Void)? = nil,
    _ body: (VICIMessage, VICIMessage) throws -> Void
  ) throws {
    let mapped = AuthenticatedPortalSnapshotMapper.mapClassified(snapshot)
    if let failure = mapped.failure { throw Failure.catalog(failure) }
    let selected = mapped.candidates.filter { $0.summary.displayName == target.resourceDisplayName }
    guard !selected.isEmpty else { throw Failure.selectionMissing }
    guard selected.count == 1 else { throw Failure.selectionAmbiguous(selected.count) }
    do {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        snapshot, handle: selected[0].summary.handle
      ) { start in
        try NativeTrialMaterial.withRequests(
          snapshot: start, target: target.host, connectionName: name,
          includePrivateRule: includePrivateRule, proposalNumber: proposalNumber,
          observeGateway: observeGateway, diagnosticSink: diagnosticSink, body)
      }
    } catch let error as AuthenticatedPortalValidatedSnapshotError {
      if case .incompleteSnapshot(let field) = error { throw Failure.snapshotIncomplete(field) }
      throw Failure.snapshotRejected
    }
  }
}
