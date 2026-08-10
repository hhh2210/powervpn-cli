import Foundation

package enum NetworkCleanupObservationState: String, Encodable, Equatable, Error, Sendable {
  case observed
  case commandFailed = "command_failed"
  case outputTooLarge = "output_too_large"
  case invalidOutput = "invalid_output"
  case changedDuringCapture = "changed_during_capture"
}

package struct NetworkCleanupFingerprint: Equatable, Sendable {
  package let state: NetworkCleanupObservationState
  package let itemCount: Int
  package let sha256: String?

  package static func observed(count: Int, sha256: String) -> Self {
    Self(state: .observed, itemCount: count, sha256: sha256)
  }

  package static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(state: state, itemCount: 0, sha256: nil)
  }

  package var isObserved: Bool {
    state == .observed && itemCount >= 0
      && sha256.map(Self.isLowercaseSHA256) == true
  }

  private static func isLowercaseSHA256(_ value: String) -> Bool {
    value.utf8.count == 64
      && value.utf8.allSatisfy {
        (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
      }
  }
}

package struct NetworkCleanupInterfaceSnapshot: Equatable, Sendable {
  package let inventory: NetworkCleanupFingerprint
  package let utunCount: Int
  let utunTokens: Set<Data>

  package static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(inventory: .unavailable(state), utunCount: 0, utunTokens: [])
  }

  package var isObserved: Bool {
    inventory.isObserved && utunCount == utunTokens.count
  }
}

package struct NetworkCleanupRouteSnapshot: Equatable, Sendable {
  package let structural: NetworkCleanupFingerprint
  package let persistent: NetworkCleanupFingerprint
  package let selectedRouteMatchCount: Int
  let selectedRouteTokens: Set<Data>
  let effectiveSelectedRoute: NetworkCleanupEffectiveRouteSnapshot?

  package init(
    structural: NetworkCleanupFingerprint,
    persistent: NetworkCleanupFingerprint,
    selectedRouteMatchCount: Int,
    selectedRouteTokens: Set<Data>,
    effectiveSelectedRoute: NetworkCleanupEffectiveRouteSnapshot? = nil
  ) {
    self.structural = structural
    self.persistent = persistent
    self.selectedRouteMatchCount = selectedRouteMatchCount
    self.selectedRouteTokens = selectedRouteTokens
    self.effectiveSelectedRoute = effectiveSelectedRoute
  }

  package static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(
      structural: .unavailable(state),
      persistent: .unavailable(state),
      selectedRouteMatchCount: 0,
      selectedRouteTokens: []
    )
  }

  package var isObserved: Bool {
    structural.isObserved && persistent.isObserved
      && selectedRouteMatchCount == selectedRouteTokens.count
      && (effectiveSelectedRoute?.isObserved ?? true)
  }
}

package struct NetworkCleanupSurgeSnapshot: Equatable, Sendable {
  package let fingerprint: NetworkCleanupFingerprint
  package let mainProcessCount: Int
  package let extensionProcessCount: Int
  package let helperProcessCount: Int

  package static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(
      fingerprint: .unavailable(state),
      mainProcessCount: 0,
      extensionProcessCount: 0,
      helperProcessCount: 0
    )
  }

  package var isObserved: Bool {
    fingerprint.isObserved && mainProcessCount >= 0 && extensionProcessCount >= 0
      && helperProcessCount >= 0
      && mainProcessCount + extensionProcessCount + helperProcessCount
        == fingerprint.itemCount
  }
}

/// Non-Codable local state retained only for one bounded connect/cleanup window.
package struct NetworkCleanupSnapshot: Equatable, Sendable {
  package let defaultRoute: NetworkCleanupFingerprint
  package let dns: NetworkCleanupFingerprint
  package let interfaces: NetworkCleanupInterfaceSnapshot
  package let ipv4Routes: NetworkCleanupRouteSnapshot
  package let ipv6Routes: NetworkCleanupRouteSnapshot
  package let surge: NetworkCleanupSurgeSnapshot
  package let vendorProcesses: NetworkCleanupVendorProcessSnapshot
  package let helperGeneration: VendorHelperGenerationSnapshot
  package let helperObservationState: NetworkCleanupObservationState

  package static func unavailable(_ state: NetworkCleanupObservationState) -> Self {
    Self(
      defaultRoute: .unavailable(state),
      dns: .unavailable(state),
      interfaces: .unavailable(state),
      ipv4Routes: .unavailable(state),
      ipv6Routes: .unavailable(state),
      surge: .unavailable(state),
      vendorProcesses: .unavailable(state),
      helperGeneration: .unavailable,
      helperObservationState: state
    )
  }

  package var complete: Bool {
    defaultRoute.isObserved && dns.isObserved && interfaces.isObserved
      && ipv4Routes.isObserved && ipv6Routes.isObserved && surge.isObserved
      && helperObservationState == .observed
      && (helperGeneration.exactInactive || helperGeneration.exactRunning)
      && vendorProcesses.isConsistent(with: helperGeneration)
  }
}

package struct NetworkCleanupResult: Encodable, Equatable, Sendable {
  package let complete: Bool
  package let defaultRouteRestored: Bool
  package let dnsRestored: Bool
  package let interfacesRestored: Bool
  package let utunRestored: Bool
  package let persistentRoutesRestored: Bool
  package let selectedRouteResidueCount: Int
  package let surgeStateRestored: Bool
  package let vendorProcessesRestored: Bool
  package let helperGenerationRestored: Bool
  package let structuralRouteTablesEqual: Bool
  package let containsSecrets = false
  package let containsRawRoutes = false
  package let containsRawState = false

  package var allDimensionsRestored: Bool {
    complete && defaultRouteRestored && dnsRestored && interfacesRestored
      && utunRestored && persistentRoutesRestored
      && selectedRouteResidueCount == 0 && surgeStateRestored
      && vendorProcessesRestored && helperGenerationRestored
  }
}

package enum NetworkCleanupAssessment {
  package static func baselineStable(
    _ first: NetworkCleanupSnapshot,
    _ second: NetworkCleanupSnapshot
  ) -> Bool {
    guard first.complete, second.complete,
      first.helperGeneration.exactInactive,
      second.helperGeneration.exactInactive
    else { return false }
    return first.defaultRoute == second.defaultRoute
      && first.dns == second.dns
      && first.interfaces == second.interfaces
      && first.ipv4Routes.persistent == second.ipv4Routes.persistent
      && first.ipv6Routes.persistent == second.ipv6Routes.persistent
      && first.surge == second.surge
      && first.vendorProcesses == second.vendorProcesses
      && first.helperGeneration == second.helperGeneration
  }

  package static func assess(
    before: NetworkCleanupSnapshot,
    after: NetworkCleanupSnapshot,
    startRequestSent: Bool
  ) -> NetworkCleanupResult {
    let complete = before.complete && after.complete
    let helperRelation = VendorHelperGenerationAssessment.assess(
      before: before.helperGeneration,
      after: after.helperGeneration,
      replyPeerGenerationValidated: false
    ).relation
    let helperRestored =
      startRequestSent
      ? helperRelation == .launchedAndExited
      : helperRelation == .inactive
    let selectedResidue = after.ipv4Routes.selectedRouteTokens
      .subtracting(before.ipv4Routes.selectedRouteTokens).count
    return NetworkCleanupResult(
      complete: complete,
      defaultRouteRestored: complete && before.defaultRoute == after.defaultRoute,
      dnsRestored: complete && before.dns == after.dns,
      interfacesRestored: complete && before.interfaces.inventory == after.interfaces.inventory,
      utunRestored: complete && before.interfaces.utunTokens == after.interfaces.utunTokens,
      persistentRoutesRestored: complete
        && before.ipv4Routes.persistent == after.ipv4Routes.persistent
        && before.ipv6Routes.persistent == after.ipv6Routes.persistent,
      selectedRouteResidueCount: complete ? selectedResidue : 0,
      surgeStateRestored: complete && before.surge == after.surge,
      vendorProcessesRestored: complete && before.vendorProcesses == after.vendorProcesses,
      helperGenerationRestored: complete && helperRestored,
      structuralRouteTablesEqual: complete
        && before.ipv4Routes.structural == after.ipv4Routes.structural
        && before.ipv6Routes.structural == after.ipv6Routes.structural
    )
  }
}
