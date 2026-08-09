import Testing

@testable import PowerVPNCore

@Suite struct VendorHelperGenerationTests {
  @Test func classifiesColdLaunchAndBindsReplyPeer() {
    let before = snapshot(running: false, pid: nil, runs: 11)
    let after = snapshot(running: true, pid: 400, runs: 12)

    let assessment = VendorHelperGenerationAssessment.assess(
      before: before,
      after: after,
      replyPeerGenerationValidated: true
    )

    #expect(assessment.relation == .launched)
    #expect(assessment.replyPeerMatchesObservedGeneration)
  }

  @Test func stableGenerationNeverInheritsReplyTimeBinding() {
    let before = snapshot(running: true, pid: 400, runs: 12)
    let after = snapshot(running: true, pid: 400, runs: 12)

    let assessment = VendorHelperGenerationAssessment.assess(
      before: before,
      after: after,
      replyPeerGenerationValidated: true
    )

    #expect(assessment.relation == .stable)
    #expect(!assessment.replyPeerMatchesObservedGeneration)
  }

  @Test func detectsPIDReuseAndMissingLaunchdEvidence() {
    let before = snapshot(running: true, pid: 400, runs: 12)
    let reusedPID = snapshot(running: true, pid: 400, runs: 13)
    let unavailable = VendorHelperGenerationSnapshot(
      launchdObserved: false,
      running: false,
      inactiveConfirmed: false,
      activeCount: nil,
      pid: nil,
      runs: nil
    )

    #expect(
      VendorHelperGenerationAssessment.assess(
        before: before,
        after: reusedPID,
        replyPeerGenerationValidated: true
      ).relation == .changed
    )
    #expect(
      VendorHelperGenerationAssessment.assess(
        before: unavailable,
        after: reusedPID,
        replyPeerGenerationValidated: true
      ).relation == .unavailable
    )
    #expect(
      VendorHelperGenerationAssessment.assess(
        before: snapshot(running: false, pid: nil, runs: 11),
        after: snapshot(running: true, pid: 400, runs: 13),
        replyPeerGenerationValidated: true
      ).relation == .changed
    )
  }

  @Test func exitedGenerationRequiresDirectReplyTimeBinding() {
    let before = snapshot(running: false, pid: nil, runs: 11)
    let after = snapshot(running: false, pid: nil, runs: 12)

    let bound = VendorHelperGenerationAssessment.assess(
      before: before,
      after: after,
      replyPeerGenerationValidated: true
    )
    let unbound = VendorHelperGenerationAssessment.assess(
      before: before,
      after: after,
      replyPeerGenerationValidated: false
    )

    #expect(bound.relation == .launchedAndExited)
    #expect(bound.replyPeerMatchesObservedGeneration)
    #expect(unbound.relation == .launchedAndExited)
    #expect(!unbound.replyPeerMatchesObservedGeneration)
  }

  @Test func parsesUniqueTopLevelInactiveAndRunningSnapshots() {
    let inactive = LaunchdVendorHelperSnapshotParser.parse(
      launchdText(
        """
          active count = 0
          state = not running
          nested = {
            active count = 9
            state = running
            runs = 999
            pid = 999
          }
          runs = 11
        """))
    #expect(inactive.launchdObserved)
    #expect(inactive.inactiveConfirmed)
    #expect(inactive.exactInactive)
    #expect(inactive.activeCount == 0)
    #expect(inactive.pid == nil)
    #expect(inactive.runs == 11)

    let running = LaunchdVendorHelperSnapshotParser.parse(
      launchdText(
        """
          active count = 2
          state = running
          pid = 400
          runs = 12
        """))
    #expect(running.launchdObserved)
    #expect(running.running)
    #expect(!running.inactiveConfirmed)
    #expect(running.exactRunning)
    #expect(running.activeCount == 2)
    #expect(running.pid == 400)
    #expect(running.runs == 12)
  }

  @Test func launchdParserRejectsMissingDuplicateUnknownAndContradictoryState() {
    let invalidBodies = [
      """
        active count = 0
        state = not running
      """,
      """
        active count = 0
        active count = 0
        state = not running
        runs = 11
      """,
      """
        active count = 0
        state = not running
        state = not running
        runs = 11
      """,
      """
        active count = 0
        state = not running
        runs = 11
        runs = 12
      """,
      """
        active count = 0
        state = waiting
        runs = 11
      """,
      """
        active count = 0
        state = not running
        pid = 400
        runs = 11
      """,
      """
        active count = 1
        state = running
        runs = 12
      """,
      """
        active count = 0
        state = running
        pid = 400
        runs = 12
      """,
    ]
    for body in invalidBodies {
      let snapshot = LaunchdVendorHelperSnapshotParser.parse(launchdText(body))
      #expect(!snapshot.launchdObserved)
      #expect(!snapshot.inactiveConfirmed)
      #expect(!snapshot.exactInactive)
      #expect(!snapshot.exactRunning)
      #expect(snapshot.activeCount == nil)
      #expect(snapshot.pid == nil)
      #expect(snapshot.runs == nil)
    }
  }

  @Test func contradictoryPublicSnapshotCannotSatisfyExactInactivePreflightState() {
    let contradiction = VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: false,
      inactiveConfirmed: true,
      activeCount: 1,
      pid: nil,
      runs: 11
    )
    #expect(!contradiction.exactInactive)
  }

  @Test func launchdParserRejectsMalformedRootBoundaries() {
    for text in [
      "",
      "system/com.leadsec.wrong-xpc = {\n active count = 0\n state = not running\n runs = 1\n}",
      "system/com.leadsec.charon-xpc = {\n active count = 0\n state = not running\n runs = 1",
      launchdText("active count = -1\nstate = not running\nruns = 1"),
    ] {
      let snapshot = LaunchdVendorHelperSnapshotParser.parse(text)
      #expect(!snapshot.launchdObserved)
      #expect(!snapshot.inactiveConfirmed)
    }
  }

  @Test func preflightRequiresEveryColdStartGate() {
    let safe = VendorXPCPreflightEvidence(
      guiProcessAbsent: true,
      helperProcessAbsent: true,
      otherVendorHelperProcessesAbsent: true,
      helperLaunchdInactive: true,
      dnsRecoveryFileAbsent: true,
      vendorLogRotationSafe: true
    )
    #expect(safe.safeToProbe)

    for blocked in [
      VendorXPCPreflightEvidence(
        guiProcessAbsent: false,
        helperProcessAbsent: true,
        otherVendorHelperProcessesAbsent: true,
        helperLaunchdInactive: true,
        dnsRecoveryFileAbsent: true,
        vendorLogRotationSafe: true
      ),
      VendorXPCPreflightEvidence(
        guiProcessAbsent: true,
        helperProcessAbsent: false,
        otherVendorHelperProcessesAbsent: true,
        helperLaunchdInactive: true,
        dnsRecoveryFileAbsent: true,
        vendorLogRotationSafe: true
      ),
      VendorXPCPreflightEvidence(
        guiProcessAbsent: true,
        helperProcessAbsent: true,
        otherVendorHelperProcessesAbsent: false,
        helperLaunchdInactive: true,
        dnsRecoveryFileAbsent: true,
        vendorLogRotationSafe: true
      ),
      VendorXPCPreflightEvidence(
        guiProcessAbsent: true,
        helperProcessAbsent: true,
        otherVendorHelperProcessesAbsent: true,
        helperLaunchdInactive: false,
        dnsRecoveryFileAbsent: true,
        vendorLogRotationSafe: true
      ),
      VendorXPCPreflightEvidence(
        guiProcessAbsent: true,
        helperProcessAbsent: true,
        otherVendorHelperProcessesAbsent: true,
        helperLaunchdInactive: true,
        dnsRecoveryFileAbsent: false,
        vendorLogRotationSafe: true
      ),
      VendorXPCPreflightEvidence(
        guiProcessAbsent: true,
        helperProcessAbsent: true,
        otherVendorHelperProcessesAbsent: true,
        helperLaunchdInactive: true,
        dnsRecoveryFileAbsent: true,
        vendorLogRotationSafe: false
      ),
    ] {
      #expect(!blocked.safeToProbe)
    }
  }

  private func snapshot(
    running: Bool,
    pid: Int?,
    runs: Int
  ) -> VendorHelperGenerationSnapshot {
    VendorHelperGenerationSnapshot(
      launchdObserved: true,
      running: running,
      inactiveConfirmed: !running,
      activeCount: running ? 1 : 0,
      pid: pid,
      runs: runs
    )
  }
}

private func launchdText(_ body: String) -> String {
  """
  system/com.leadsec.charon-xpc = {
  \(body)
  }
  """
}
