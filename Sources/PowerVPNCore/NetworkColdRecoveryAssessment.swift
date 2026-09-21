import Foundation

/// Value-free proof that two bounded observations describe one cold, stable
/// network state for the currently authorized profile. This is a new recovery
/// basis; it does not claim that an earlier session restored its own baseline.
package struct NetworkColdRecoveryAssessment: Encodable, Equatable, Sendable {
  package let capturesComplete: Bool
  package let helperExactInactive: Bool
  package let helperGenerationStable: Bool
  package let initialHelperGenerationMatches: Bool
  package let vendorProcessesAbsent: Bool
  package let defaultRouteStable: Bool
  package let dnsStable: Bool
  package let interfaceInventoryStable: Bool
  package let utunStable: Bool
  package let persistentRoutesStable: Bool
  package let structuralRoutesStable: Bool
  package let surgeStable: Bool
  package let firstSelectedRouteResidueCount: Int
  package let secondSelectedRouteResidueCount: Int
  package let firstEffectiveSelectedRouteAbsent: Bool
  package let secondEffectiveSelectedRouteAbsent: Bool
  package let passed: Bool
  package let containsSecrets = false
  package let containsRawState = false
  package let containsRawRoutes = false

  package init(
    initialGeneration: VendorHelperGenerationSnapshot,
    first: NetworkCleanupSnapshot,
    second: NetworkCleanupSnapshot
  ) {
    capturesComplete = first.complete && second.complete
    helperExactInactive =
      first.helperGeneration.exactInactive && second.helperGeneration.exactInactive
    helperGenerationStable = first.helperGeneration == second.helperGeneration
    initialHelperGenerationMatches = initialGeneration == first.helperGeneration
    vendorProcessesAbsent =
      Self.vendorProcessesAbsent(first.vendorProcesses)
      && Self.vendorProcessesAbsent(second.vendorProcesses)
    defaultRouteStable = first.defaultRoute == second.defaultRoute
    dnsStable = first.dns == second.dns
    interfaceInventoryStable = first.interfaces.inventory == second.interfaces.inventory
    utunStable = first.interfaces.utunTokens == second.interfaces.utunTokens
    persistentRoutesStable =
      first.ipv4Routes.persistent == second.ipv4Routes.persistent
      && first.ipv6Routes.persistent == second.ipv6Routes.persistent
    structuralRoutesStable =
      first.ipv4Routes.structural == second.ipv4Routes.structural
      && first.ipv6Routes.structural == second.ipv6Routes.structural
    surgeStable = first.surge == second.surge
    firstSelectedRouteResidueCount = first.ipv4Routes.selectedRouteMatchCount
    secondSelectedRouteResidueCount = second.ipv4Routes.selectedRouteMatchCount
    firstEffectiveSelectedRouteAbsent = Self.effectiveSelectedRouteAbsent(first.ipv4Routes)
    secondEffectiveSelectedRouteAbsent = Self.effectiveSelectedRouteAbsent(second.ipv4Routes)
    passed =
      capturesComplete
      && helperExactInactive
      && helperGenerationStable
      && initialHelperGenerationMatches
      && vendorProcessesAbsent
      && defaultRouteStable
      && dnsStable
      && interfaceInventoryStable
      && utunStable
      && persistentRoutesStable
      && structuralRoutesStable
      && surgeStable
      && firstSelectedRouteResidueCount == 0
      && secondSelectedRouteResidueCount == 0
      && first.ipv4Routes.selectedRouteTokens.isEmpty
      && second.ipv4Routes.selectedRouteTokens.isEmpty
      && firstEffectiveSelectedRouteAbsent
      && secondEffectiveSelectedRouteAbsent
  }

  package init(
    first: NetworkCleanupSnapshot,
    second: NetworkCleanupSnapshot
  ) {
    self.init(
      initialGeneration: first.helperGeneration,
      first: first,
      second: second
    )
  }

  private static func vendorProcessesAbsent(
    _ snapshot: NetworkCleanupVendorProcessSnapshot
  ) -> Bool {
    snapshot.isObserved
      && snapshot.fingerprint.itemCount == 0
      && snapshot.officialGUIProcessCount == 0
      && snapshot.charonProcessCount == 0
      && snapshot.ipsecProcessCount == 0
      && snapshot.shellProcessCount == 0
      && snapshot.identityTokens.isEmpty
  }

  private static func effectiveSelectedRouteAbsent(
    _ snapshot: NetworkCleanupRouteSnapshot
  ) -> Bool {
    guard let effective = snapshot.effectiveSelectedRoute else { return false }
    return effective.state == .observed && effective.selectedRouteToken == nil
  }
}
