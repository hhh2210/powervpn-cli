import Foundation

package enum VendorAppNonLogoutHandoffApproval: String, Encodable, Sendable {
  case accepted
  case denied
  case unavailable
}

package enum VendorAppNonLogoutHandoffOutcome: String, Encodable, Sendable {
  case ready
  case preflightRejected = "preflight_rejected"
  case cursorRejected = "cursor_rejected"
  case launchRejected = "launch_rejected"
  case approvalDenied = "approval_denied"
  case approvalUnavailable = "approval_unavailable"
  case sourceNotReady = "source_not_ready"
  case terminationRejected = "termination_rejected"
  case cleanupUnproven = "cleanup_unproven"
  case proofRejected = "proof_rejected"
  case cancelled
}

package enum VendorAppNonLogoutHandoffSourceObservation:
  String, Encodable, Equatable, Sendable
{
  case notObserved = "not_observed"
  case ready
  case sourceUnavailable = "source_unavailable"
  case unsafeSource = "unsafe_source"
  case changedDuringRead = "changed_during_read"
  case appendTooLarge = "append_too_large"
  case staleLogout = "stale_logout"
  case malformedRecord = "malformed_record"
  case resourceUnavailable = "resource_unavailable"
  case incompleteRecord = "incomplete_record"
  case snapshotIncomplete = "snapshot_incomplete"
  case missingSourceSeal = "missing_source_seal"

  init(_ error: VendorAppSessionSnapshotError) {
    switch error {
    case .unavailable: self = .sourceUnavailable
    case .unsafeSource: self = .unsafeSource
    case .changedDuringRead: self = .changedDuringRead
    case .appendTooLarge: self = .appendTooLarge
    case .stale: self = .staleLogout
    case .malformed: self = .malformedRecord
    case .resourceUnavailable: self = .resourceUnavailable
    case .incomplete: self = .incompleteRecord
    }
  }
}

package struct VendorAppNonLogoutHandoffReport: Encodable, Sendable {
  package static let schemaVersion = 2

  package let schemaVersion = Self.schemaVersion
  package let outcome: VendorAppNonLogoutHandoffOutcome
  package let onboardingMode = "vendor_once"
  package let assurance = "current_machine_pinned"
  package let resourceDisplayName = VendorAppSessionSnapshotMaterial.resourceName
  package let baselineStable: Bool
  package let cursorPersisted: Bool
  package let officialAppLaunched: Bool
  package let secondApproval: VendorAppNonLogoutHandoffApproval?
  package let forceTerminationAccepted: Bool
  package let exactReceiverTerminated: Bool
  package let sourceSnapshotComplete: Bool
  package let sourceObservation: VendorAppNonLogoutHandoffSourceObservation
  package let proofPersisted: Bool
  package let officialAppStillRunning: Bool
  package let cleanup: VendorAppNonLogoutHandoffCleanupProof?
  package let containsSecrets = false
  package let snapshotSerialized = false
  package let normalQuitRequested = false

  package init(
    outcome: VendorAppNonLogoutHandoffOutcome,
    baselineStable: Bool,
    cursorPersisted: Bool,
    officialAppLaunched: Bool,
    secondApproval: VendorAppNonLogoutHandoffApproval?,
    forceTerminationAccepted: Bool,
    exactReceiverTerminated: Bool,
    sourceSnapshotComplete: Bool,
    sourceObservation: VendorAppNonLogoutHandoffSourceObservation = .notObserved,
    proofPersisted: Bool,
    officialAppStillRunning: Bool,
    cleanup: VendorAppNonLogoutHandoffCleanupProof?
  ) {
    self.outcome = outcome
    self.baselineStable = baselineStable
    self.cursorPersisted = cursorPersisted
    self.officialAppLaunched = officialAppLaunched
    self.secondApproval = secondApproval
    self.forceTerminationAccepted = forceTerminationAccepted
    self.exactReceiverTerminated = exactReceiverTerminated
    self.sourceSnapshotComplete = sourceSnapshotComplete
    self.sourceObservation = sourceObservation
    self.proofPersisted = proofPersisted
    self.officialAppStillRunning = officialAppStillRunning
    self.cleanup = cleanup
  }

  package var readyForConnectOnce: Bool {
    outcome == .ready && proofPersisted && cleanup?.allDimensionsRestored == true
  }
}
