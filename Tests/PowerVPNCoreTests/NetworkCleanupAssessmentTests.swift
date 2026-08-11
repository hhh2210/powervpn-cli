import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkCleanupAssessmentTests {
  @Test func baselineIgnoresStructuralChurnAndMatcherAvailabilityDifference() {
    let first = snapshot(
      helperRuns: 10,
      structuralV4: fingerprint("1"),
      selected: []
    )
    let second = snapshot(
      helperRuns: 10,
      structuralV4: fingerprint("2"),
      selected: [Data([1])]
    )
    #expect(NetworkCleanupAssessment.baselineStable(first, second))
  }

  @Test func baselineRequiresColdInactiveHelperAndNoVendorProcess() {
    let cold = snapshot(helperRuns: 10)
    let active = activeSnapshot(from: cold, helperRuns: 11)

    #expect(active.complete)
    #expect(!NetworkCleanupAssessment.baselineStable(active, active))
    #expect(!NetworkCleanupAssessment.baselineStable(cold, active))
  }

  @Test func cleanupResidueIsDirectionalAndPreexistingRouteIsAllowed() {
    let existing = Data([1])
    let added = Data([2])
    let before = snapshot(helperRuns: 10, selected: [existing])
    let after = snapshot(helperRuns: 11, selected: [existing, added])
    let residue = NetworkCleanupAssessment.assess(
      before: before,
      after: after,
      startRequestSent: true
    )
    #expect(residue.complete)
    #expect(residue.selectedRouteResidueCount == 1)
    #expect(residue.helperGenerationRestored)
    #expect(residue.vendorProcessesRestored)
    #expect(!residue.allDimensionsRestored)

    let restored = NetworkCleanupAssessment.assess(
      before: before,
      after: snapshot(helperRuns: 11, selected: [existing]),
      startRequestSent: true
    )
    #expect(restored.selectedRouteResidueCount == 0)
    #expect(restored.allDimensionsRestored)
  }

  @Test func structuralRouteDifferenceCannotPassCleanup() {
    let before = snapshot(helperRuns: 10, structuralV4: fingerprint("1"))
    let after = snapshot(helperRuns: 11, structuralV4: fingerprint("2"))
    let result = NetworkCleanupAssessment.assess(
      before: before,
      after: after,
      startRequestSent: true
    )

    #expect(!result.structuralRouteTablesEqual)
    #expect(!result.allDimensionsRestored)
  }

  @Test func vendorProcessResidueCannotPassCleanup() {
    let before = snapshot(helperRuns: 10)
    let residueToken = Data([4])
    let after = snapshot(
      helperRuns: 11,
      vendorProcesses: vendorSnapshot(
        charon: 0,
        ipsec: 1,
        tokens: [residueToken]
      )
    )
    let result = NetworkCleanupAssessment.assess(
      before: before,
      after: after,
      startRequestSent: true
    )

    #expect(!after.complete)
    #expect(!result.vendorProcessesRestored)
    #expect(!result.allDimensionsRestored)
  }

  @Test func helperRelationDependsOnWhetherStartWasSent() {
    let before = snapshot(helperRuns: 10)
    let unchanged = snapshot(helperRuns: 10)
    let exited = snapshot(helperRuns: 11)
    #expect(
      NetworkCleanupAssessment.assess(
        before: before, after: unchanged, startRequestSent: false
      ).helperGenerationRestored
    )
    #expect(
      !NetworkCleanupAssessment.assess(
        before: before, after: unchanged, startRequestSent: true
      ).helperGenerationRestored
    )
    #expect(
      NetworkCleanupAssessment.assess(
        before: before, after: exited, startRequestSent: true
      ).helperGenerationRestored
    )
  }

  @Test func unavailableOrInconsistentComponentsCannotPass() throws {
    var unavailable = snapshot(helperRuns: 10)
    unavailable = NetworkCleanupSnapshot(
      defaultRoute: .unavailable(.invalidOutput),
      dns: unavailable.dns,
      interfaces: unavailable.interfaces,
      ipv4Routes: unavailable.ipv4Routes,
      ipv6Routes: unavailable.ipv6Routes,
      surge: unavailable.surge,
      vendorProcesses: unavailable.vendorProcesses,
      helperGeneration: unavailable.helperGeneration,
      helperObservationState: unavailable.helperObservationState
    )
    let result = NetworkCleanupAssessment.assess(
      before: unavailable,
      after: snapshot(helperRuns: 10),
      startRequestSent: false
    )
    #expect(!result.complete)
    #expect(!result.allDimensionsRestored)

    let inconsistentSurge = NetworkCleanupSurgeSnapshot(
      fingerprint: NetworkCleanupFingerprint(
        state: .observed,
        itemCount: 2,
        sha256: String(repeating: "a", count: 64)
      ),
      mainProcessCount: 1,
      extensionProcessCount: 1,
      helperProcessCount: 1
    )
    #expect(!inconsistentSurge.isObserved)

    let encoded = try JSONEncoder().encode(result)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(!json.contains("sha256"))
    #expect(!json.contains("selectedRouteTokens"))
    #expect(json.contains("\"containsSecrets\":false"))
    #expect(json.contains("\"containsRawRoutes\":false"))
    #expect(json.contains("\"containsRawState\":false"))
  }
}

private func snapshot(
  helperRuns: Int,
  structuralV4: NetworkCleanupFingerprint? = nil,
  selected: Set<Data> = [],
  vendorProcesses: NetworkCleanupVendorProcessSnapshot = vendorSnapshot()
) -> NetworkCleanupSnapshot {
  let common = fingerprint("a")
  return NetworkCleanupSnapshot(
    defaultRoute: common,
    dns: fingerprint("b"),
    interfaces: NetworkCleanupInterfaceSnapshot(
      inventory: fingerprint("c"),
      utunCount: 1,
      utunTokens: [Data([9])]
    ),
    ipv4Routes: NetworkCleanupRouteSnapshot(
      structural: structuralV4 ?? fingerprint("d"),
      persistent: fingerprint("e"),
      selectedRouteMatchCount: selected.count,
      selectedRouteTokens: selected
    ),
    ipv6Routes: NetworkCleanupRouteSnapshot(
      structural: fingerprint("f"),
      persistent: fingerprint("0"),
      selectedRouteMatchCount: 0,
      selectedRouteTokens: []
    ),
    surge: NetworkCleanupSurgeSnapshot(
      fingerprint: NetworkCleanupFingerprint(
        state: .observed,
        itemCount: 3,
        sha256: String(repeating: "1", count: 64)
      ),
      mainProcessCount: 1,
      extensionProcessCount: 1,
      helperProcessCount: 1
    ),
    vendorProcesses: vendorProcesses,
    helperGeneration: VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: false,
      inactiveConfirmed: true,
      activeCount: 0,
      pid: nil,
      runs: helperRuns
    ),
    helperObservationState: .observed
  )
}

private func vendorSnapshot(
  charon: Int = 0,
  ipsec: Int = 0,
  tokens: Set<Data> = []
) -> NetworkCleanupVendorProcessSnapshot {
  NetworkCleanupVendorProcessSnapshot(
    fingerprint: .observed(
      count: tokens.count,
      sha256: String(repeating: "2", count: 64)
    ),
    officialGUIProcessCount: 0,
    charonProcessCount: charon,
    ipsecProcessCount: ipsec,
    shellProcessCount: 0,
    identityTokens: tokens
  )
}

private func activeSnapshot(
  from source: NetworkCleanupSnapshot,
  helperRuns: Int
) -> NetworkCleanupSnapshot {
  NetworkCleanupSnapshot(
    defaultRoute: source.defaultRoute,
    dns: source.dns,
    interfaces: source.interfaces,
    ipv4Routes: source.ipv4Routes,
    ipv6Routes: source.ipv6Routes,
    surge: source.surge,
    vendorProcesses: vendorSnapshot(
      charon: 1,
      tokens: [Data([3])]
    ),
    helperGeneration: VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: true,
      inactiveConfirmed: false,
      activeCount: 1,
      pid: 41,
      runs: helperRuns
    ),
    helperObservationState: .observed
  )
}

private func fingerprint(_ nibble: Character) -> NetworkCleanupFingerprint {
  NetworkCleanupFingerprint(
    state: .observed,
    itemCount: 1,
    sha256: String(repeating: nibble, count: 64)
  )
}
