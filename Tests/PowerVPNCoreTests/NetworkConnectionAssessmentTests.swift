import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NetworkConnectionAssessmentTests {
  @Test func selectedBindingAndSingleGenerationProveActivePath() throws {
    let before = connectionSnapshot(
      running: false,
      runs: 10,
      selected: [Data([1])],
      effectiveSelected: Data([1]),
      utuns: [Data([8])]
    )
    let active = connectionSnapshot(
      running: true,
      runs: 11,
      selected: [Data([1]), Data([2])],
      effectiveSelected: Data([2]),
      utuns: [Data([8]), Data([9])],
      defaultRoute: fingerprint("b"),
      dns: fingerprint("c"),
      persistentV4: fingerprint("d")
    )

    let result = NetworkConnectionAssessment.assess(before: before, active: active)
    #expect(result.complete)
    #expect(result.helperSingleRunningGeneration)
    #expect(result.surgeStable)
    #expect(result.vendorGUIAbsent)
    #expect(result.unrelatedVendorHelpersAbsent)
    #expect(result.selectedRouteBindingDeltaCount == 1)
    #expect(result.effectiveSelectedRouteBindingIntroduced)
    #expect(result.newUtunCount == 1)
    #expect(result.defaultRouteChanged)
    #expect(result.dnsChanged)
    #expect(result.persistentRoutesChanged)
    #expect(result.selectedResourcePathProven)

    let json = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
    #expect(json.contains("\"selectedResourcePathProven\":true"))
    #expect(json.contains("\"effectiveSelectedRouteBindingIntroduced\":true"))
    #expect(json.contains("\"containsRawRoutes\":false"))
    #expect(!json.contains("selectedRouteTokens"))
    #expect(!json.contains("utunTokens"))
  }

  @Test func newUtunIsReportedButNotRequired() {
    let before = connectionSnapshot(running: false, runs: 20)
    let active = connectionSnapshot(
      running: true,
      runs: 21,
      selected: [Data([4])],
      effectiveSelected: Data([4])
    )

    let result = NetworkConnectionAssessment.assess(before: before, active: active)
    #expect(result.newUtunCount == 0)
    #expect(result.selectedResourcePathProven)
  }

  @Test func missingSelectedDeltaOrWrongGenerationCannotProvePath() {
    let before = connectionSnapshot(running: false, runs: 30)
    let noRoute = connectionSnapshot(running: true, runs: 31)
    let skippedGeneration = connectionSnapshot(
      running: true,
      runs: 32,
      selected: [Data([5])],
      effectiveSelected: Data([5])
    )

    let noRouteResult = NetworkConnectionAssessment.assess(before: before, active: noRoute)
    let generationResult = NetworkConnectionAssessment.assess(
      before: before,
      active: skippedGeneration
    )
    #expect(noRouteResult.selectedRouteBindingDeltaCount == 0)
    #expect(!noRouteResult.selectedResourcePathProven)
    #expect(!generationResult.helperSingleRunningGeneration)
    #expect(!generationResult.selectedResourcePathProven)
  }

  @Test func guiOrUnrelatedHelperMakesActiveObservationIncomplete() {
    let before = connectionSnapshot(running: false, runs: 40)
    let active = connectionSnapshot(
      running: true,
      runs: 41,
      selected: [Data([6])],
      effectiveSelected: Data([6]),
      gui: 1,
      ipsec: 1
    )

    let result = NetworkConnectionAssessment.assess(before: before, active: active)
    #expect(!active.complete)
    #expect(!result.complete)
    #expect(!result.vendorGUIAbsent)
    #expect(!result.unrelatedVendorHelpersAbsent)
    #expect(!result.selectedResourcePathProven)
  }

  @Test func effectiveRouteMustBeTheNewSelectedBinding() {
    let routeA = Data([7])
    let routeB = Data([8])
    let before = connectionSnapshot(
      running: false,
      runs: 50,
      selected: [routeA],
      effectiveSelected: routeA
    )
    let parallelRouteButStillA = connectionSnapshot(
      running: true,
      runs: 51,
      selected: [routeA, routeB],
      effectiveSelected: routeA
    )
    let effectiveB = connectionSnapshot(
      running: true,
      runs: 51,
      selected: [routeA, routeB],
      effectiveSelected: routeB
    )

    let wrong = NetworkConnectionAssessment.assess(
      before: before,
      active: parallelRouteButStillA
    )
    let proven = NetworkConnectionAssessment.assess(before: before, active: effectiveB)

    #expect(wrong.selectedRouteBindingDeltaCount == 1)
    #expect(!wrong.effectiveSelectedRouteBindingIntroduced)
    #expect(!wrong.selectedResourcePathProven)
    #expect(proven.selectedRouteBindingDeltaCount == 1)
    #expect(proven.effectiveSelectedRouteBindingIntroduced)
    #expect(proven.selectedResourcePathProven)
  }
}

private func connectionSnapshot(
  running: Bool,
  runs: Int,
  selected: Set<Data> = [],
  effectiveSelected: Data? = nil,
  utuns: Set<Data> = [],
  defaultRoute: NetworkCleanupFingerprint = fingerprint("0"),
  dns: NetworkCleanupFingerprint = fingerprint("1"),
  persistentV4: NetworkCleanupFingerprint = fingerprint("2"),
  gui: Int = 0,
  ipsec: Int = 0
) -> NetworkCleanupSnapshot {
  let common = fingerprint("a")
  let charon = running ? 1 : 0
  let processTokens = Set((0..<(charon + gui + ipsec)).map { Data([UInt8($0)]) })
  return NetworkCleanupSnapshot(
    defaultRoute: defaultRoute,
    dns: dns,
    interfaces: NetworkCleanupInterfaceSnapshot(
      inventory: common,
      utunCount: utuns.count,
      utunTokens: utuns
    ),
    ipv4Routes: NetworkCleanupRouteSnapshot(
      structural: common,
      persistent: persistentV4,
      selectedRouteMatchCount: selected.count,
      selectedRouteTokens: selected,
      effectiveSelectedRoute: .observed(selectedRouteToken: effectiveSelected)
    ),
    ipv6Routes: NetworkCleanupRouteSnapshot(
      structural: common,
      persistent: common,
      selectedRouteMatchCount: 0,
      selectedRouteTokens: []
    ),
    surge: surgeSnapshot(),
    vendorProcesses: NetworkCleanupVendorProcessSnapshot(
      fingerprint: .observed(
        count: processTokens.count,
        sha256: String(repeating: "3", count: 64)
      ),
      officialGUIProcessCount: gui,
      charonProcessCount: charon,
      ipsecProcessCount: ipsec,
      shellProcessCount: 0,
      identityTokens: processTokens
    ),
    helperGeneration: VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: running,
      inactiveConfirmed: !running,
      activeCount: running ? 1 : 0,
      pid: running ? 50 : nil,
      runs: runs
    ),
    helperObservationState: .observed
  )
}

private func surgeSnapshot() -> NetworkCleanupSurgeSnapshot {
  NetworkCleanupSurgeSnapshot(
    fingerprint: .observed(
      count: 0,
      sha256: String(repeating: "4", count: 64)
    ),
    mainProcessCount: 0,
    extensionProcessCount: 0,
    helperProcessCount: 0
  )
}

private func fingerprint(_ nibble: Character) -> NetworkCleanupFingerprint {
  .observed(count: 1, sha256: String(repeating: nibble, count: 64))
}
