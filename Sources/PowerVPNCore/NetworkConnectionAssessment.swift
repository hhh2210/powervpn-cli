package struct NetworkConnectionResult: Encodable, Equatable, Sendable {
  package let complete: Bool
  package let helperSingleRunningGeneration: Bool
  package let surgeStable: Bool
  package let vendorGUIAbsent: Bool
  package let unrelatedVendorHelpersAbsent: Bool
  package let selectedRouteBindingDeltaCount: Int
  package let effectiveSelectedRouteBindingIntroduced: Bool
  package let newUtunCount: Int
  package let defaultRouteChanged: Bool
  package let dnsChanged: Bool
  package let persistentRoutesChanged: Bool
  package let selectedResourcePathProven: Bool
  package let containsRawRoutes = false
  package let containsRawState = false
  package let containsSecrets = false
}

package enum NetworkConnectionAssessment {
  package static func assess(
    before: NetworkCleanupSnapshot,
    active: NetworkCleanupSnapshot
  ) -> NetworkConnectionResult {
    let complete = before.complete && active.complete
    let helperSingleRunning =
      complete
      && VendorHelperGenerationAssessment.assess(
        before: before.helperGeneration,
        after: active.helperGeneration,
        replyPeerGenerationValidated: false
      ).relation == .launched
    let surgeStable = complete && before.surge == active.surge
    let guiAbsent = complete && active.vendorProcesses.officialGUIProcessCount == 0
    let unrelatedAbsent =
      complete
      && active.vendorProcesses.ipsecProcessCount == 0
      && active.vendorProcesses.shellProcessCount == 0
    let selectedDelta =
      complete
      ? active.ipv4Routes.selectedRouteTokens
        .subtracting(before.ipv4Routes.selectedRouteTokens).count
      : 0
    let selectedDeltaTokens = active.ipv4Routes.selectedRouteTokens
      .subtracting(before.ipv4Routes.selectedRouteTokens)
    let effectiveSelectedRouteIsNew =
      active.ipv4Routes.effectiveSelectedRoute?.selectedRouteToken
      .map(selectedDeltaTokens.contains) == true
    let newUtunCount =
      complete
      ? active.interfaces.utunTokens.subtracting(before.interfaces.utunTokens).count
      : 0
    let defaultRouteChanged = complete && before.defaultRoute != active.defaultRoute
    let dnsChanged = complete && before.dns != active.dns
    let persistentRoutesChanged =
      complete
      && (before.ipv4Routes.persistent != active.ipv4Routes.persistent
        || before.ipv6Routes.persistent != active.ipv6Routes.persistent)
    return NetworkConnectionResult(
      complete: complete,
      helperSingleRunningGeneration: helperSingleRunning,
      surgeStable: surgeStable,
      vendorGUIAbsent: guiAbsent,
      unrelatedVendorHelpersAbsent: unrelatedAbsent,
      selectedRouteBindingDeltaCount: selectedDelta,
      effectiveSelectedRouteBindingIntroduced: effectiveSelectedRouteIsNew,
      newUtunCount: newUtunCount,
      defaultRouteChanged: defaultRouteChanged,
      dnsChanged: dnsChanged,
      persistentRoutesChanged: persistentRoutesChanged,
      selectedResourcePathProven: complete && helperSingleRunning && surgeStable
        && guiAbsent && unrelatedAbsent && selectedDelta > 0
        && effectiveSelectedRouteIsNew
    )
  }
}
