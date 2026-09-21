import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkColdRecoveryAssessmentTests {
  @Test func stableColdProfilePassesWithoutEncodingRawState() throws {
    let first = coldRecoverySnapshot()
    let assessment = NetworkColdRecoveryAssessment(first: first, second: first)

    #expect(assessment.passed)
    #expect(assessment.capturesComplete)
    #expect(assessment.helperExactInactive)
    #expect(assessment.helperGenerationStable)
    #expect(assessment.vendorProcessesAbsent)
    #expect(assessment.firstSelectedRouteResidueCount == 0)
    #expect(assessment.secondSelectedRouteResidueCount == 0)
    #expect(assessment.firstEffectiveSelectedRouteAbsent)
    #expect(assessment.secondEffectiveSelectedRouteAbsent)

    let json = String(decoding: try JSONEncoder().encode(assessment), as: UTF8.self)
    #expect(json.contains("\"passed\":true"))
    #expect(json.contains("\"containsSecrets\":false"))
    #expect(json.contains("\"containsRawState\":false"))
    #expect(json.contains("\"containsRawRoutes\":false"))
    #expect(!json.contains(String(repeating: "a", count: 64)))
    #expect(!json.contains("selectedRouteTokens"))
  }

  @Test func structuralRouteChangeFailsEvenWhenPersistentRoutesMatch() {
    let first = coldRecoverySnapshot()
    let second = coldRecoverySnapshot(ipv4Structural: fingerprint("9"))
    let assessment = NetworkColdRecoveryAssessment(first: first, second: second)

    #expect(assessment.persistentRoutesStable)
    #expect(!assessment.structuralRoutesStable)
    #expect(!assessment.passed)
  }

  @Test func selectedRouteResidueAndEffectiveBindingFailClosed() {
    let token = Data([7])
    let residue = coldRecoverySnapshot(
      selectedRouteTokens: [token],
      effectiveSelectedRoute: .observed(selectedRouteToken: token)
    )
    let assessment = NetworkColdRecoveryAssessment(first: residue, second: residue)

    #expect(assessment.capturesComplete)
    #expect(assessment.firstSelectedRouteResidueCount == 1)
    #expect(!assessment.firstEffectiveSelectedRouteAbsent)
    #expect(!assessment.passed)
  }

  @Test func missingEffectiveRouteObservationFailsClosed() {
    let snapshot = coldRecoverySnapshot(effectiveSelectedRoute: nil)
    let assessment = NetworkColdRecoveryAssessment(first: snapshot, second: snapshot)

    #expect(assessment.capturesComplete)
    #expect(!assessment.firstEffectiveSelectedRouteAbsent)
    #expect(!assessment.secondEffectiveSelectedRouteAbsent)
    #expect(!assessment.passed)
  }

  @Test func changedInactiveGenerationAndDNSFailClosed() {
    let first = coldRecoverySnapshot(helperRuns: 8)
    let second = coldRecoverySnapshot(helperRuns: 9, dns: fingerprint("8"))
    let assessment = NetworkColdRecoveryAssessment(first: first, second: second)

    #expect(assessment.helperExactInactive)
    #expect(!assessment.helperGenerationStable)
    #expect(!assessment.dnsStable)
    #expect(!assessment.passed)
  }
}

private func coldRecoverySnapshot(
  helperRuns: Int = 8,
  dns: NetworkCleanupFingerprint = fingerprint("b"),
  ipv4Structural: NetworkCleanupFingerprint = fingerprint("d"),
  selectedRouteTokens: Set<Data> = [],
  effectiveSelectedRoute: NetworkCleanupEffectiveRouteSnapshot? = .observed(
    selectedRouteToken: nil
  )
) -> NetworkCleanupSnapshot {
  NetworkCleanupSnapshot(
    defaultRoute: fingerprint("a"),
    dns: dns,
    interfaces: NetworkCleanupInterfaceSnapshot(
      inventory: fingerprint("c"),
      utunCount: 1,
      utunTokens: [Data([1])]
    ),
    ipv4Routes: NetworkCleanupRouteSnapshot(
      structural: ipv4Structural,
      persistent: fingerprint("e"),
      selectedRouteMatchCount: selectedRouteTokens.count,
      selectedRouteTokens: selectedRouteTokens,
      effectiveSelectedRoute: effectiveSelectedRoute
    ),
    ipv6Routes: NetworkCleanupRouteSnapshot(
      structural: fingerprint("f"),
      persistent: fingerprint("0"),
      selectedRouteMatchCount: 0,
      selectedRouteTokens: []
    ),
    surge: NetworkCleanupSurgeSnapshot(
      fingerprint: .observed(count: 0, sha256: String(repeating: "1", count: 64)),
      mainProcessCount: 0,
      extensionProcessCount: 0,
      helperProcessCount: 0
    ),
    vendorProcesses: NetworkCleanupVendorProcessSnapshot(
      fingerprint: .observed(count: 0, sha256: String(repeating: "2", count: 64)),
      officialGUIProcessCount: 0,
      charonProcessCount: 0,
      ipsecProcessCount: 0,
      shellProcessCount: 0,
      identityTokens: []
    ),
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

private func fingerprint(_ nibble: Character) -> NetworkCleanupFingerprint {
  .observed(count: 1, sha256: String(repeating: nibble, count: 64))
}
