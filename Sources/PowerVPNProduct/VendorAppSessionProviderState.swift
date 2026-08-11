import Foundation
import PowerVPNCore

final class VendorAppSessionProviderState: @unchecked Sendable {
  private let lock = NSLock()
  private let cursor: VendorAppOnboardingCursor?
  private let sourceIsCurrent: @Sendable (VendorAppSessionSnapshotMaterial) -> Bool
  private let handoffProofIsCurrent:
    @Sendable (VendorAppOnboardingCursor, VendorAppSessionSnapshotMaterial) -> Bool
  private var material: VendorAppSessionSnapshotMaterial?
  private var acquisitionIssued = false

  init() {
    sourceIsCurrent = { $0.sourceIsCurrent }
    handoffProofIsCurrent = Self.installedHandoffProofIsCurrent
    let loaded: (VendorAppOnboardingCursor, VendorAppSessionSnapshotMaterial)?
    do {
      let cursor = try VendorAppOnboardingCursor.loadDefault()
      guard cursor.handoffProof?.isBound(to: cursor) == true else {
        throw VendorAppSessionSnapshotError.stale
      }
      let source = try VendorAppSessionSnapshotSource(cursor: cursor)
      let material = try source.load().makeMaterial()
      guard material.validation.complete,
        Self.installedHandoffProofIsCurrent(cursor, material)
      else {
        material.erase()
        throw VendorAppSessionSnapshotError.incomplete
      }
      loaded = (cursor, material)
    } catch {
      loaded = nil
    }
    cursor = loaded?.0
    material = loaded?.1
  }

  init(
    cursor: VendorAppOnboardingCursor?,
    material: VendorAppSessionSnapshotMaterial?,
    sourceIsCurrent: @escaping @Sendable (VendorAppSessionSnapshotMaterial) -> Bool = {
      $0.sourceIsCurrent
    },
    handoffProofIsCurrent:
      @escaping @Sendable (
        VendorAppOnboardingCursor, VendorAppSessionSnapshotMaterial
      ) -> Bool = { _, _ in true }
  ) {
    self.cursor = cursor
    self.material = material
    self.sourceIsCurrent = sourceIsCurrent
    self.handoffProofIsCurrent = handoffProofIsCurrent
  }

  var isAvailable: Bool {
    lock.withLock { currentMaterialLocked() != nil }
  }

  func readinessCandidate() -> ProductResourceCandidate? {
    lock.withLock {
      guard let material = currentMaterialLocked() else { return nil }
      let validation = material.validation
      guard validation.complete else { return nil }
      return ProductResourceCandidate(summary: material.summary, validation: validation)
    }
  }

  func claimForAcquisition() -> VendorAppSessionSnapshotMaterial? {
    let claim: (VendorAppOnboardingCursor, VendorAppSessionSnapshotMaterial)? = lock.withLock {
      guard let cursor, let material = currentMaterialLocked() else { return nil }
      acquisitionIssued = true
      self.material = nil
      return (cursor, material)
    }
    guard let (cursor, material) = claim else { return nil }
    guard material.sourceIsCurrent, handoffProofIsCurrent(cursor, material) else {
      material.erase()
      return nil
    }
    do {
      try cursor.consumeDefault()
      return material
    } catch {
      material.erase()
      return nil
    }
  }

  private func currentMaterialLocked() -> VendorAppSessionSnapshotMaterial? {
    guard !acquisitionIssued, let cursor, let material else { return nil }
    guard sourceIsCurrent(material), handoffProofIsCurrent(cursor, material) else {
      self.material = nil
      material.erase()
      return nil
    }
    return material
  }

  private static func installedHandoffProofIsCurrent(
    _ cursor: VendorAppOnboardingCursor,
    _ material: VendorAppSessionSnapshotMaterial
  ) -> Bool {
    guard let proof = cursor.handoffProof else { return false }
    let generation = LaunchdVendorHelperGenerationObserver().observe()
    return proof.accepts(material: material, generation: generation)
      && InstalledVendorXPCPreflightChecker().check(generation: generation).safeToProbe
  }

  deinit {
    lock.lock()
    let pending = material
    material = nil
    lock.unlock()
    pending?.erase()
  }
}
