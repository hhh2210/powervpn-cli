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

package struct VendorAppNonLogoutHandoffReport: Encodable, Sendable {
  package static let schemaVersion = 1

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
  package let proofPersisted: Bool
  package let officialAppStillRunning: Bool
  package let cleanup: VendorAppNonLogoutHandoffCleanupProof?
  package let containsSecrets = false
  package let snapshotSerialized = false
  package let normalQuitRequested = false

  package var readyForConnectOnce: Bool {
    outcome == .ready && proofPersisted && cleanup?.allDimensionsRestored == true
  }
}
