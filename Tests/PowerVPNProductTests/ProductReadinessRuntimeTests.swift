import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNProduct

@Suite struct ProductReadinessRuntimeTests {
  @Test func currentMachineShapeReturnsOneConcreteSnapshotBlocker() throws {
    let runtime = ProductReadinessRuntime(
      observer: FixedProductObservation(makeObservation())
    )

    let doctor = runtime.doctor()
    #expect(doctor.productState == .blocked)
    #expect(doctor.onboardingMode == .vendorOnce)
    #expect(doctor.profileSource == .sealedInstalledConfiguration)
    #expect(doctor.resourceSource == .unavailable)
    #expect(doctor.firstMissingField == .sessionID)
    #expect(doctor.blocker == .authenticatedPortalSnapshotUnavailable)
    #expect(!doctor.networkRequested)
    #expect(!doctor.helperMutationRequested)

    let resources = runtime.resources()
    #expect(resources.productState == .blocked)
    #expect(resources.selectableResourceCount == 0)
    #expect(resources.selectableResources.isEmpty)
    #expect(resources.blocker == .authenticatedPortalSnapshotUnavailable)

    let snapshot = runtime.snapshotDryRun()
    #expect(!snapshot.snapshotComplete)
    #expect(snapshot.firstMissingField == .sessionID)
    #expect(
      snapshot.fields.prefix(4).map(\.availability) == [
        .generated, .generated, .generated, .generated,
      ])
    #expect(snapshot.fields[4].field == .sessionID)
    #expect(snapshot.fields[4].availability == .missingRequired)
    #expect(!snapshot.snapshotSerialized)
    #expect(!snapshot.containsSecrets)

    let encoded = try JSONEncoder().encode(snapshot)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(!json.contains("synthetic-session-value"))
    #expect(!json.contains("vpn.example.invalid"))
  }

  @Test func helperStatusSeparatesObservationFromDirectProbe() {
    let runtime = ProductReadinessRuntime(
      observer: FixedProductObservation(makeObservation())
    )

    let report = runtime.helperStatus()
    #expect(report.productState == .degraded)
    #expect(report.directXPCStatus == .notProbed)
    #expect(!report.liveProbePerformed)
    #expect(report.probeAvailable)
    #expect(report.preflightRequired)
    #expect(report.preflightSafe)
    #expect(report.blocker == .directXPCNotProbed)
    #expect(!report.serverContactRequested)
    #expect(!report.helperMutationRequested)
    #expect(report.generation.runs == 19)
  }

  @Test func completeAuthorizedSnapshotBecomesReadyWithoutSerializingIt() {
    let candidate = ProductResourceCandidate(
      summary: productSummary("resource"),
      validation: completeValidation()
    )
    let observation = makeObservation(
      directXPCStatus: .currentReachable,
      resourceSource: .authenticatedPortalSnapshot,
      resourceCandidates: [candidate]
    )
    let runtime = ProductReadinessRuntime(observer: FixedProductObservation(observation))

    let doctor = runtime.doctor()
    #expect(doctor.productState == .ready)
    #expect(doctor.snapshotComplete)
    #expect(doctor.firstMissingField == nil)
    #expect(doctor.blocker == nil)

    let resources = runtime.resources()
    #expect(resources.productState == .ready)
    #expect(resources.selectableResourceCount == 1)
    #expect(resources.selectableResources == [candidate.summary])

    let snapshot = runtime.snapshotDryRun()
    #expect(snapshot.productState == .ready)
    #expect(snapshot.snapshotComplete)
    #expect(snapshot.firstMissingField == nil)
    #expect(snapshot.selectedResource == candidate.summary)
    #expect(!snapshot.snapshotSerialized)
  }

  @Test func missingInstalledProfileTakesPriorityInDoctor() {
    let observation = makeObservation(profileSource: .unavailable)
    let report = ProductReadinessRuntime(
      observer: FixedProductObservation(observation)
    ).doctor()

    #expect(report.blocker == .installedConfigurationUnavailable)
    #expect(report.firstMissingField == .sessionID)
  }

  @Test func unsafeOrUnreachableHelperGetsAnExactBlocker() {
    let unsafe = makeObservation(directXPCPreflightSafe: false)
    let unsafeReport = ProductReadinessRuntime(
      observer: FixedProductObservation(unsafe)
    ).helperStatus()
    #expect(unsafeReport.productState == .blocked)
    #expect(unsafeReport.blocker == .directXPCPreflightUnsafe)
    #expect(!unsafeReport.probeAvailable)

    let unreachable = makeObservation(directXPCStatus: .currentUnreachable)
    let unreachableReport = ProductReadinessRuntime(
      observer: FixedProductObservation(unreachable)
    ).helperStatus()
    #expect(unreachableReport.productState == .blocked)
    #expect(unreachableReport.blocker == .directXPCUnreachable)
    #expect(unreachableReport.liveProbePerformed)
  }

  @Test func doctorCannotBecomeReadyWithoutCurrentHelperControl() {
    let candidate = ProductResourceCandidate(
      summary: productSummary("resource"),
      validation: completeValidation()
    )
    let observation = makeObservation(
      resourceSource: .authenticatedPortalSnapshot,
      resourceCandidates: [candidate]
    )
    let report = ProductReadinessRuntime(
      observer: FixedProductObservation(observation)
    ).doctor()

    #expect(report.snapshotComplete)
    #expect(report.productState == .blocked)
    #expect(report.blocker == .directXPCNotProbed)
  }

  @Test func snapshotFieldsCannotBeUnionedAcrossResources() {
    let firstLineage = VendorCharonStartLineage()
    let first = ProductResourceCandidate(
      summary: productSummary("one"),
      validation: VendorCharonStartValidator.validate(
        VendorCharonStartCandidate(
          lineage: firstLineage,
          common: completeCommonCandidate(lineage: firstLineage)
        )
      )
    )
    let secondLineage = VendorCharonStartLineage()
    let second = ProductResourceCandidate(
      summary: productSummary("two"),
      validation: VendorCharonStartValidator.validate(
        VendorCharonStartCandidate(
          lineage: secondLineage,
          tunnels: completeTunnelCandidates(lineage: secondLineage)
        )
      )
    )
    let observation = makeObservation(
      directXPCStatus: .currentReachable,
      resourceSource: .authenticatedPortalSnapshot,
      resourceCandidates: [first, second]
    )
    let report = ProductReadinessRuntime(
      observer: FixedProductObservation(observation)
    ).snapshotDryRun()

    #expect(!report.snapshotComplete)
    #expect(report.selectedResource == nil)
    #expect(report.firstMissingField == .sessionID)
    #expect(report.blocker == .resourceSelectionRequired)
  }

  private func makeObservation(
    directXPCStatus: DirectXPCStatus = .notProbed,
    directXPCPreflightSafe: Bool = true,
    profileSource: ProductProfileSource = .sealedInstalledConfiguration,
    resourceSource: ProductResourceSource = .unavailable,
    resourceCandidates: [ProductResourceCandidate] = []
  ) -> ProductReadinessObservation {
    ProductReadinessObservation(
      installedVersion: "3.2.1",
      installedBuild: "24572",
      installedArchitectures: ["x86_64"],
      officialGUIRunning: false,
      helperAvailable: true,
      generation: VendorHelperGenerationSnapshot(
        launchdObserved: true,
        running: false,
        inactiveConfirmed: true,
        activeCount: 0,
        pid: nil,
        runs: 19
      ),
      directXPCStatus: directXPCStatus,
      directXPCPreflightSafe: directXPCPreflightSafe,
      profileSource: profileSource,
      resourceSource: resourceSource,
      resourceCandidates: resourceCandidates
    )
  }
}
