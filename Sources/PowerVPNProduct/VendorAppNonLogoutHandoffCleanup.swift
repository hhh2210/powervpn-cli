import Foundation
import PowerVPNCore

package protocol VendorAppHandoffColdWaiting: Sendable {
  func wait(
    application: any VendorAppHandoffApplication,
    timeoutMilliseconds: Int
  ) async -> VendorHelperGenerationSnapshot?
}

package struct InstalledVendorAppHandoffColdWaiter: VendorAppHandoffColdWaiting {
  private let generationObserver: any BoundedVendorHelperGenerationObserving
  private let preflightChecker: any BoundedVendorXPCPreflightChecking
  private let now: @Sendable () -> UInt64

  package init() {
    generationObserver = InstalledBoundedVendorHelperGenerationObserver()
    preflightChecker = InstalledBoundedVendorXPCPreflightChecker()
    now = { DispatchTime.now().uptimeNanoseconds }
  }

  init(
    generationObserver: any BoundedVendorHelperGenerationObserving,
    preflightChecker: any BoundedVendorXPCPreflightChecking,
    now: @escaping @Sendable () -> UInt64
  ) {
    self.generationObserver = generationObserver
    self.preflightChecker = preflightChecker
    self.now = now
  }

  package func wait(
    application: any VendorAppHandoffApplication,
    timeoutMilliseconds: Int
  ) async -> VendorHelperGenerationSnapshot? {
    guard timeoutMilliseconds > 0,
      let duration = UInt64(exactly: timeoutMilliseconds),
      duration <= (UInt64.max / 1_000_000)
    else { return nil }
    let started = now()
    let delta = duration * 1_000_000
    guard started <= UInt64.max - delta else { return nil }
    let deadline = started + delta

    while now() < deadline {
      guard application.isTerminated || application.identityIsCurrent else { return nil }
      if application.isTerminated {
        let remaining = remainingMilliseconds(until: deadline)
        if remaining > 0,
          let generation = await observedGeneration(remaining: remaining)
        {
          let afterGeneration = remainingMilliseconds(until: deadline)
          if afterGeneration > 0 {
            let evidence = await preflightChecker.check(
              generation: generation,
              timeoutMilliseconds: min(2_000, afterGeneration)
            )
            if evidence.safeToProbe { return generation }
          }
        }
      }
      guard remainingMilliseconds(until: deadline) > 100 else { return nil }
      try? await Task.sleep(for: .milliseconds(100))
    }
    return nil
  }

  private func observedGeneration(remaining: Int) async -> VendorHelperGenerationSnapshot? {
    let generation = await generationObserver.observe(
      timeoutMilliseconds: min(2_000, remaining)
    )
    return generation.exactInactive ? generation : nil
  }

  private func remainingMilliseconds(until deadline: UInt64) -> Int {
    let current = now()
    guard current < deadline else { return 0 }
    return max(1, Int((deadline - current) / 1_000_000))
  }
}

enum VendorAppNonLogoutHandoffCleanupAssessment {
  static func assess(
    before: NetworkCleanupSnapshot,
    after: NetworkCleanupSnapshot,
    finalGeneration: VendorHelperGenerationSnapshot
  ) -> VendorAppNonLogoutHandoffCleanupProof {
    let complete = before.complete && after.complete
    let helperRunsAdvanced: Bool
    if let beforeRuns = before.helperGeneration.runs,
      let afterRuns = finalGeneration.runs
    {
      helperRunsAdvanced =
        beforeRuns < Int.max - 1
        && (afterRuns == beforeRuns + 1 || afterRuns == beforeRuns + 2)
    } else {
      helperRunsAdvanced = false
    }
    let vendorAbsent =
      after.vendorProcesses.isObserved
      && after.vendorProcesses.officialGUIProcessCount == 0
      && after.vendorProcesses.charonProcessCount == 0
      && after.vendorProcesses.ipsecProcessCount == 0
      && after.vendorProcesses.shellProcessCount == 0

    return VendorAppNonLogoutHandoffCleanupProof(
      complete: complete,
      defaultRouteRestored: complete && before.defaultRoute == after.defaultRoute,
      dnsRestored: complete && before.dns == after.dns,
      interfacesRestored: complete && before.interfaces.inventory == after.interfaces.inventory,
      utunRestored: complete && before.interfaces.utunTokens == after.interfaces.utunTokens,
      persistentRoutesRestored: complete
        && before.ipv4Routes.persistent == after.ipv4Routes.persistent
        && before.ipv6Routes.persistent == after.ipv6Routes.persistent,
      surgeStateRestored: complete && before.surge == after.surge,
      vendorProcessesAbsent: complete && vendorAbsent,
      helperInactive: complete && finalGeneration.exactInactive && helperRunsAdvanced
        && after.helperGeneration == finalGeneration,
      structuralRouteTablesEqual: complete
        && before.ipv4Routes.structural == after.ipv4Routes.structural
        && before.ipv6Routes.structural == after.ipv6Routes.structural
    )
  }
}
