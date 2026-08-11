func report(
  _ outcome: VendorAppNonLogoutHandoffOutcome,
  baselineStable: Bool = false,
  cursorPersisted: Bool = false,
  officialAppLaunched: Bool = false,
  secondApproval: VendorAppNonLogoutHandoffApproval? = nil,
  forceTerminationAccepted: Bool = false,
  exactReceiverTerminated: Bool = false,
  sourceSnapshotComplete: Bool = false,
  sourceObservation: VendorAppNonLogoutHandoffSourceObservation = .notObserved,
  proofPersisted: Bool = false,
  officialAppStillRunning: Bool = false,
  cleanup: VendorAppNonLogoutHandoffCleanupProof? = nil
) -> VendorAppNonLogoutHandoffReport {
  VendorAppNonLogoutHandoffReport(
    outcome: outcome,
    baselineStable: baselineStable,
    cursorPersisted: cursorPersisted,
    officialAppLaunched: officialAppLaunched,
    secondApproval: secondApproval,
    forceTerminationAccepted: forceTerminationAccepted,
    exactReceiverTerminated: exactReceiverTerminated,
    sourceSnapshotComplete: sourceSnapshotComplete,
    sourceObservation: sourceObservation,
    proofPersisted: proofPersisted,
    officialAppStillRunning: officialAppStillRunning,
    cleanup: cleanup
  )
}
