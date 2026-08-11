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
  case noAppendObserved = "no_append_observed"
  case windowLimitReached = "window_limit_reached"
  case recordTruncated = "record_truncated"
  case invalidEncoding = "invalid_encoding"
  case markerMissing = "marker_missing"
  case markerUnbalanced = "marker_unbalanced"
  case markerMultiplicity = "marker_multiplicity"
  case rpcMissing = "rpc_missing"
  case rpcNonScalar = "rpc_non_scalar"
  case rpcUnknown = "rpc_unknown"
  case noStartRecord = "no_start_record"
  case duplicateStartRecord = "duplicate_start_record"
  case logoutObserved = "logout_observed"
  case ambiguousRecordSet = "ambiguous_record_set"
  case dictionarySyntax = "dictionary_syntax"
  case dictionaryRootShape = "dictionary_root_shape"
  case requiredFieldMissing = "required_field_missing"
  case requiredFieldWrongType = "required_field_wrong_type"
  case resourceUnavailable = "resource_unavailable"
  case snapshotIncomplete = "snapshot_incomplete"
  case missingSourceSeal = "missing_source_seal"
}

package struct VendorAppNonLogoutHandoffSourceDiagnosis: Equatable, Sendable {
  package let observation: VendorAppNonLogoutHandoffSourceObservation
  package let requiredField: VendorAppSessionRequiredField?

  package init(
    _ observation: VendorAppNonLogoutHandoffSourceObservation,
    requiredField: VendorAppSessionRequiredField? = nil
  ) {
    self.observation = observation
    self.requiredField = requiredField
  }

  init(_ error: VendorAppSessionSnapshotError) {
    switch error {
    case .unavailable:
      self.init(VendorAppNonLogoutHandoffSourceObservation.sourceUnavailable)
    case .unsafeSource:
      self.init(VendorAppNonLogoutHandoffSourceObservation.unsafeSource)
    case .changedDuringRead:
      self.init(VendorAppNonLogoutHandoffSourceObservation.changedDuringRead)
    case .noAppendObserved:
      self.init(VendorAppNonLogoutHandoffSourceObservation.noAppendObserved)
    case .appendTooLarge:
      self.init(VendorAppNonLogoutHandoffSourceObservation.windowLimitReached)
    case .stale:
      self.init(VendorAppNonLogoutHandoffSourceObservation.logoutObserved)
    case .malformed:
      self.init(VendorAppNonLogoutHandoffSourceObservation.dictionaryRootShape)
    case .recordRejected(let reason):
      switch reason {
      case .invalidEncoding:
        self.init(VendorAppNonLogoutHandoffSourceObservation.invalidEncoding)
      case .markerMissing:
        self.init(VendorAppNonLogoutHandoffSourceObservation.markerMissing)
      case .markerUnbalanced:
        self.init(VendorAppNonLogoutHandoffSourceObservation.markerUnbalanced)
      case .markerMultiplicity:
        self.init(VendorAppNonLogoutHandoffSourceObservation.markerMultiplicity)
      case .rpcMissing:
        self.init(VendorAppNonLogoutHandoffSourceObservation.rpcMissing)
      case .rpcNonScalar:
        self.init(VendorAppNonLogoutHandoffSourceObservation.rpcNonScalar)
      case .rpcUnknown:
        self.init(VendorAppNonLogoutHandoffSourceObservation.rpcUnknown)
      case .noStartRecord:
        self.init(VendorAppNonLogoutHandoffSourceObservation.noStartRecord)
      case .duplicateStartRecord:
        self.init(VendorAppNonLogoutHandoffSourceObservation.duplicateStartRecord)
      case .ambiguousRecordSet:
        self.init(VendorAppNonLogoutHandoffSourceObservation.ambiguousRecordSet)
      case .dictionarySyntax:
        self.init(VendorAppNonLogoutHandoffSourceObservation.dictionarySyntax)
      case .dictionaryRootShape:
        self.init(VendorAppNonLogoutHandoffSourceObservation.dictionaryRootShape)
      case .windowLimitReached:
        self.init(VendorAppNonLogoutHandoffSourceObservation.windowLimitReached)
      }
    case .requiredFieldMissing(let field):
      self.init(
        VendorAppNonLogoutHandoffSourceObservation.requiredFieldMissing,
        requiredField: field
      )
    case .requiredFieldWrongType(let field):
      self.init(
        VendorAppNonLogoutHandoffSourceObservation.requiredFieldWrongType,
        requiredField: field
      )
    case .resourceUnavailable:
      self.init(VendorAppNonLogoutHandoffSourceObservation.resourceUnavailable)
    case .incomplete:
      self.init(VendorAppNonLogoutHandoffSourceObservation.recordTruncated)
    }
  }

  static let notObserved = Self(.notObserved)
  static let ready = Self(.ready)
  static let sourceUnavailable = Self(.sourceUnavailable)
  static let changedDuringRead = Self(.changedDuringRead)
  static let snapshotIncomplete = Self(.snapshotIncomplete)
  static let missingSourceSeal = Self(.missingSourceSeal)
}

package struct VendorAppNonLogoutHandoffReport: Encodable, Sendable {
  package static let schemaVersion = 4

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
  package let sourceRequiredField: VendorAppSessionRequiredField?
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
    sourceDiagnosis: VendorAppNonLogoutHandoffSourceDiagnosis = .notObserved,
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
    sourceObservation = sourceDiagnosis.observation
    sourceRequiredField = sourceDiagnosis.requiredField
    self.proofPersisted = proofPersisted
    self.officialAppStillRunning = officialAppStillRunning
    self.cleanup = cleanup
  }

  package var readyForConnectOnce: Bool {
    outcome == .ready && proofPersisted && cleanup?.allDimensionsRestored == true
  }
}
