import Foundation
import PowerVPNCore

package enum ProductM2AuthorizedResourceSelectionError: Error, Equatable, Sendable {
  case leaseClosed
  case selectionAlreadyIssued
  case startAlreadyIssued
  case invalidSelection
  case preparedSelectionMismatch
  case resourceNotFound
  case resourceAmbiguous
  case catalogRejected
  case startSnapshotRejected
  case selectedRouteCoverageRejected
  case workAborted
}

package struct ProductM2AuthorizationCloseReceipt: Equatable, Sendable {
  package let outcome: ProductM2AuthorizationCloseOutcome
  package let ownedMaterialErased: Bool
  package let sourceCloseRequested: Bool
  package let serverContactRequested: Bool

  package init(
    outcome: ProductM2AuthorizationCloseOutcome,
    ownedMaterialErased: Bool,
    sourceCloseRequested: Bool,
    serverContactRequested: Bool
  ) {
    self.outcome = outcome == .accepted && !ownedMaterialErased ? .rejected : outcome
    self.ownedMaterialErased = ownedMaterialErased
    self.sourceCloseRequested = sourceCloseRequested
    self.serverContactRequested = serverContactRequested
  }

  package static let alreadyClosed = Self(
    outcome: .alreadyClosed,
    ownedMaterialErased: false,
    sourceCloseRequested: false,
    serverContactRequested: false
  )
}

package struct ProductM2PreparedAuthorizedResource: Sendable {
  package typealias WithStartSnapshot =
    @Sendable (
      (VendorCharonStartSnapshot) throws -> Void
    ) throws -> Void

  let summary: ProductResourceSummary
  let selectedRoutes: VendorCharonSelectedRouteMatcher
  let requiredTargetIPv4: UInt32
  fileprivate let withStartSnapshot: WithStartSnapshot

  package init(
    summary: ProductResourceSummary,
    selectedRoutes: VendorCharonSelectedRouteMatcher,
    requiredTargetIPv4: UInt32,
    withStartSnapshot: @escaping WithStartSnapshot
  ) {
    self.summary = summary
    self.selectedRoutes = selectedRoutes
    self.requiredTargetIPv4 = requiredTargetIPv4
    self.withStartSnapshot = withStartSnapshot
  }
}

/// Owns one authorization generation; selection/start are one-shot, and close
/// erases provider-owned material before its first suspension.
package actor ProductM2AuthorizedResourceLease {
  package typealias Catalog = @Sendable () throws -> [ProductResourceCandidate]
  package typealias Prepare =
    @Sendable (String, UInt32) throws -> ProductM2PreparedAuthorizedResource
  package typealias EraseOwnedMaterial = @Sendable () -> Bool
  package typealias Close =
    @Sendable (ProductM2StageDeadline) async -> ProductM2AuthorizationCloseReceipt
  package typealias CommitStartAuthorization = @Sendable () throws -> Void
  private enum State { case open, closing, closed }
  package nonisolated let source: ProductM2AuthorizationSource
  private var state = State.open
  private var readCatalog: Catalog?
  private var cachedCatalog: [ProductResourceCandidate]?
  private var prepare: Prepare?
  private var eraseOwnedMaterial: EraseOwnedMaterial?
  private var close: Close?
  private var ownedMaterialErased = false
  private var selectionID: UUID?
  private var selectionIssued = false
  private var withStartSnapshot: ProductM2PreparedAuthorizedResource.WithStartSnapshot?
  private var selectedRoutes: VendorCharonSelectedRouteMatcher?
  private var requiredTargetIPv4: UInt32?
  private var commitStartAuthorization: CommitStartAuthorization?
  private var startIssued = false
  package init(
    source: ProductM2AuthorizationSource,
    catalog: @escaping Catalog,
    prepare: @escaping Prepare,
    eraseOwnedMaterial: @escaping EraseOwnedMaterial,
    close: @escaping Close,
    commitStartAuthorization: @escaping CommitStartAuthorization = {}
  ) {
    self.source = source
    readCatalog = catalog
    self.prepare = prepare
    self.eraseOwnedMaterial = eraseOwnedMaterial
    self.close = close
    self.commitStartAuthorization = commitStartAuthorization
  }
  deinit {
    _ = eraseOwnedMaterial?()
  }
  package func catalog() throws -> [ProductResourceCandidate] {
    guard state == .open else {
      throw ProductM2AuthorizedResourceSelectionError.leaseClosed
    }
    if let cachedCatalog { return cachedCatalog }
    guard let readCatalog else {
      throw ProductM2AuthorizedResourceSelectionError.catalogRejected
    }
    self.readCatalog = nil
    let catalog = try readCatalog()
    guard ProductResourceCatalog.isValid(catalog) else {
      throw ProductM2AuthorizedResourceSelectionError.catalogRejected
    }
    cachedCatalog = catalog
    return catalog
  }
  package func selectUnique(
    displayName: String,
    requiredTargetIPv4: UInt32
  ) throws -> ProductM2AuthorizedResourceSelection {
    guard state == .open else {
      throw ProductM2AuthorizedResourceSelectionError.leaseClosed
    }
    guard !selectionIssued, let prepare else {
      throw ProductM2AuthorizedResourceSelectionError.selectionAlreadyIssued
    }
    selectionIssued = true
    self.prepare = nil
    let matches = try catalog().filter { $0.summary.displayName == displayName }
    guard !matches.isEmpty else {
      throw ProductM2AuthorizedResourceSelectionError.resourceNotFound
    }
    guard matches.count == 1 else {
      throw ProductM2AuthorizedResourceSelectionError.resourceAmbiguous
    }
    let candidate = matches[0]
    let prepared = try prepare(candidate.summary.handle, requiredTargetIPv4)
    guard prepared.summary == candidate.summary,
      prepared.requiredTargetIPv4 == requiredTargetIPv4,
      prepared.selectedRoutes.requiredTargetIPv4 == requiredTargetIPv4
    else {
      throw ProductM2AuthorizedResourceSelectionError.preparedSelectionMismatch
    }
    let id = UUID()
    selectionID = id
    withStartSnapshot = prepared.withStartSnapshot
    selectedRoutes = prepared.selectedRoutes
    self.requiredTargetIPv4 = requiredTargetIPv4
    return ProductM2AuthorizedResourceSelection(
      summary: prepared.summary,
      selectedRoutes: prepared.selectedRoutes,
      selectionID: id,
      lease: self
    )
  }

  fileprivate func beginStart(
    selectionID: UUID,
    control: ProductM2ControlAdapter,
    deadline: ProductM2StageDeadline,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) throws -> ProductM2PendingStart {
    guard state == .open else {
      throw ProductM2AuthorizedResourceSelectionError.leaseClosed
    }
    guard self.selectionID == selectionID else {
      throw ProductM2AuthorizedResourceSelectionError.invalidSelection
    }
    guard !startIssued, let withStartSnapshot, let selectedRoutes,
      let requiredTargetIPv4, let commitStartAuthorization
    else {
      throw ProductM2AuthorizedResourceSelectionError.startAlreadyIssued
    }
    startIssued = true
    self.withStartSnapshot = nil
    self.selectedRoutes = nil
    self.requiredTargetIPv4 = nil
    self.commitStartAuthorization = nil
    var pending: ProductM2PendingStart?
    var invocationCount = 0
    do {
      try withStartSnapshot { snapshot in
        invocationCount += 1
        if pending != nil { return }
        guard invocationCount == 1,
          snapshot.isBound(
            to: selectedRoutes,
            requiredTargetIPv4: requiredTargetIPv4
          )
        else {
          throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
        }
        guard !Task.isCancelled,
          let timeoutMilliseconds = deadline.remainingMilliseconds(cappedAt: 2_000)
        else {
          throw ProductM2AuthorizedResourceSelectionError.workAborted
        }
        pending = try control.beginStart(
          snapshot: snapshot,
          timeoutMilliseconds: timeoutMilliseconds,
          peerGenerationValidator: peerGenerationValidator,
          commitStartAuthorization: commitStartAuthorization
        )
      }
    } catch let error as ProductM2AuthorizedResourceSelectionError {
      // Submission linearizes mutation; wrapper replay/post-call throws cannot erase it.
      if let pending { return pending }
      if error == .workAborted { throw error }
      throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
    } catch {
      if let pending { return pending }
      throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
    }
    guard let pending else {
      throw ProductM2AuthorizedResourceSelectionError.startSnapshotRejected
    }
    return pending
  }

  /// Drops all start/catalog material synchronously on this actor while retaining
  /// only the source-close operation needed by final shutdown.
  package func eraseStartMaterial() -> Bool {
    guard state == .open else { return ownedMaterialErased }
    readCatalog = nil
    cachedCatalog = nil
    prepare = nil
    selectionID = nil
    withStartSnapshot = nil
    selectedRoutes = nil
    requiredTargetIPv4 = nil
    commitStartAuthorization = nil
    guard !ownedMaterialErased else { return true }
    let erase = eraseOwnedMaterial
    eraseOwnedMaterial = nil
    ownedMaterialErased = erase?() ?? false
    return ownedMaterialErased
  }

  package func closeAndErase(
    deadline: ProductM2StageDeadline
  ) async -> ProductM2AuthorizationCloseReceipt {
    guard state == .open else { return .alreadyClosed }
    let erasedBeforeAwait = eraseStartMaterial()
    state = .closing
    let close = close
    self.close = nil

    let sourceReceipt =
      await close?(deadline)
      ?? ProductM2AuthorizationCloseReceipt(
        outcome: .rejected,
        ownedMaterialErased: false,
        sourceCloseRequested: false,
        serverContactRequested: false
      )
    let receipt = ProductM2AuthorizationCloseReceipt(
      outcome: sourceReceipt.outcome,
      ownedMaterialErased: erasedBeforeAwait && sourceReceipt.ownedMaterialErased,
      sourceCloseRequested: sourceReceipt.sourceCloseRequested,
      serverContactRequested: sourceReceipt.serverContactRequested
    )
    state = .closed
    return receipt
  }
}

package struct ProductM2AuthorizedResourceSelection: Sendable {
  package let summary: ProductResourceSummary
  package let selectedRoutes: VendorCharonSelectedRouteMatcher
  private let selectionID: UUID
  private let lease: ProductM2AuthorizedResourceLease

  fileprivate init(
    summary: ProductResourceSummary,
    selectedRoutes: VendorCharonSelectedRouteMatcher,
    selectionID: UUID,
    lease: ProductM2AuthorizedResourceLease
  ) {
    self.summary = summary
    self.selectedRoutes = selectedRoutes
    self.selectionID = selectionID
    self.lease = lease
  }

  package func beginStart(
    control: ProductM2ControlAdapter,
    deadline: ProductM2StageDeadline,
    peerGenerationValidator: @escaping @Sendable () async -> Bool
  ) async throws -> ProductM2PendingStart {
    try await lease.beginStart(
      selectionID: selectionID,
      control: control,
      deadline: deadline,
      peerGenerationValidator: peerGenerationValidator
    )
  }
}
