import Foundation
import PowerVPNCore
import PowerVPNProduct

struct UserProductCleanupEvidenceReceipt: Codable, Equatable, Sendable {
  let complete: Bool
  let defaultRouteRestored: Bool
  let dnsRestored: Bool
  let interfacesRestored: Bool
  let utunRestored: Bool
  let persistentRoutesRestored: Bool
  let selectedRouteResidueCount: Int
  let surgeStateRestored: Bool
  let vendorProcessesRestored: Bool
  let helperGenerationRestored: Bool
  let structuralRouteTablesEqual: Bool

  init(_ evidence: ProductM2CleanupEvidence) {
    complete = evidence.complete
    defaultRouteRestored = evidence.defaultRouteRestored
    dnsRestored = evidence.dnsRestored
    interfacesRestored = evidence.interfacesRestored
    utunRestored = evidence.utunRestored
    persistentRoutesRestored = evidence.persistentRoutesRestored
    selectedRouteResidueCount = evidence.selectedRouteResidueCount
    surgeStateRestored = evidence.surgeStateRestored
    vendorProcessesRestored = evidence.vendorProcessesRestored
    helperGenerationRestored = evidence.helperGenerationRestored
    structuralRouteTablesEqual = evidence.structuralRouteTablesEqual
  }

  var allDimensionsRestored: Bool {
    complete && defaultRouteRestored && dnsRestored && interfacesRestored
      && utunRestored && persistentRoutesRestored
      && selectedRouteResidueCount == 0 && surgeStateRestored
      && vendorProcessesRestored && helperGenerationRestored
      && structuralRouteTablesEqual
  }
}

struct UserProductOriginalCleanupReceipt: Codable, Equatable, Sendable {
  let schemaVersion: Int
  let cleanupPath: String
  let stopOutcome: String
  let emergencyStopOutcome: String
  let authorizationClose: String
  let authorizationOwnedMaterialErased: Bool
  let cleanupCaptureState: String?
  let cleanupCaptureRetryReason: String?
  let cleanupCaptureAttemptCount: Int
  let cleanupEvidence: UserProductCleanupEvidenceReceipt
  let cleanupVerified: Bool
  let containsSecrets: Bool

  init(_ report: ProductPersistentTunnelShutdownReport) {
    schemaVersion = 1
    cleanupPath = report.cleanupPath.rawValue
    stopOutcome = report.stopOutcome.rawValue
    emergencyStopOutcome = report.emergencyStopOutcome.rawValue
    authorizationClose = report.authorizationClose.rawValue
    authorizationOwnedMaterialErased = report.authorizationOwnedMaterialErased
    cleanupCaptureState = report.cleanupCaptureState?.rawValue
    cleanupCaptureRetryReason = report.cleanupCaptureRetryReason?.rawValue
    cleanupCaptureAttemptCount = report.cleanupCaptureAttemptCount
    cleanupEvidence = UserProductCleanupEvidenceReceipt(report.cleanupEvidence)
    cleanupVerified = report.cleanupVerified
    containsSecrets = false
  }

  var valid: Bool {
    schemaVersion == 1 && !containsSecrets
      && ProductM2CleanupPath(rawValue: cleanupPath) != nil
      && ProductM2ControlOutcome(rawValue: stopOutcome) != nil
      && ProductM2ControlOutcome(rawValue: emergencyStopOutcome) != nil
      && ProductM2AuthorizationCloseOutcome(rawValue: authorizationClose) != nil
      && (cleanupCaptureState.map {
        ProductM2CleanupCaptureState(rawValue: $0) != nil
      } ?? true)
      && (cleanupCaptureRetryReason.map {
        ProductM2CleanupCaptureRetryReason(rawValue: $0) != nil
      } ?? true)
      && (0...2).contains(cleanupCaptureAttemptCount)
      && (!cleanupVerified
        || (cleanupPath != ProductM2CleanupPath.cleanupUnproven.rawValue
          && (authorizationClose == ProductM2AuthorizationCloseOutcome.accepted.rawValue
            || authorizationClose == ProductM2AuthorizationCloseOutcome.notRequired.rawValue)
          && authorizationOwnedMaterialErased
          && cleanupCaptureState == ProductM2CleanupCaptureState.measuredComplete.rawValue
          && (1...2).contains(cleanupCaptureAttemptCount)
          && cleanupEvidence.allDimensionsRestored))
  }
}

struct UserProductRecoveryEvidenceReceipt: Codable, Equatable, Sendable {
  let capturesComplete: Bool
  let helperExactInactive: Bool
  let helperGenerationStable: Bool
  let initialHelperGenerationMatches: Bool
  let vendorProcessesAbsent: Bool
  let defaultRouteStable: Bool
  let dnsStable: Bool
  let interfaceInventoryStable: Bool
  let utunStable: Bool
  let persistentRoutesStable: Bool
  let structuralRoutesStable: Bool
  let surgeStable: Bool
  let firstSelectedRouteResidueCount: Int
  let secondSelectedRouteResidueCount: Int
  let firstEffectiveSelectedRouteAbsent: Bool
  let secondEffectiveSelectedRouteAbsent: Bool
  let passed: Bool

  var recomputedPassed: Bool {
    capturesComplete && helperExactInactive && helperGenerationStable
      && initialHelperGenerationMatches
      && vendorProcessesAbsent && defaultRouteStable && dnsStable
      && interfaceInventoryStable && utunStable && persistentRoutesStable
      && structuralRoutesStable && surgeStable
      && firstSelectedRouteResidueCount == 0
      && secondSelectedRouteResidueCount == 0
      && firstEffectiveSelectedRouteAbsent && secondEffectiveSelectedRouteAbsent
  }

  var valid: Bool {
    firstSelectedRouteResidueCount >= 0 && secondSelectedRouteResidueCount >= 0
      && passed == recomputedPassed
  }

  init(_ evidence: NetworkColdRecoveryAssessment) {
    capturesComplete = evidence.capturesComplete
    helperExactInactive = evidence.helperExactInactive
    helperGenerationStable = evidence.helperGenerationStable
    initialHelperGenerationMatches = evidence.initialHelperGenerationMatches
    vendorProcessesAbsent = evidence.vendorProcessesAbsent
    defaultRouteStable = evidence.defaultRouteStable
    dnsStable = evidence.dnsStable
    interfaceInventoryStable = evidence.interfaceInventoryStable
    utunStable = evidence.utunStable
    persistentRoutesStable = evidence.persistentRoutesStable
    structuralRoutesStable = evidence.structuralRoutesStable
    surgeStable = evidence.surgeStable
    firstSelectedRouteResidueCount = evidence.firstSelectedRouteResidueCount
    secondSelectedRouteResidueCount = evidence.secondSelectedRouteResidueCount
    firstEffectiveSelectedRouteAbsent = evidence.firstEffectiveSelectedRouteAbsent
    secondEffectiveSelectedRouteAbsent = evidence.secondEffectiveSelectedRouteAbsent
    passed = evidence.passed
  }
}

struct UserProductRecoveryReceipt: Codable, Equatable, Sendable {
  let schemaVersion: Int
  let measurementID: String
  let measuredAtUnixSeconds: Int64
  let originalSessionID: String
  let target: String
  let originalFailure: String?
  let basis: String
  let outcome: String
  let failure: String?
  let originalCleanupRestored: Bool
  let permitsReconnect: Bool
  let noActiveMaster: Bool
  let mutationLeaseAcquired: Bool
  let preflightSafe: Bool
  let authorizationClose: String
  let authorizationOwnedMaterialErased: Bool
  let serverContactRequested: Bool
  let captureAttemptCount: Int
  let evidence: UserProductRecoveryEvidenceReceipt?
  let containsSecrets: Bool

  init(
    report: ProductCleanupRecoveryReport,
    originalSessionID: String,
    target: String,
    originalFailure: String?,
    noActiveMaster: Bool,
    measuredAtUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970),
    measurementID: String = UUID().uuidString.lowercased()
  ) {
    schemaVersion = 1
    self.measurementID = measurementID
    self.measuredAtUnixSeconds = measuredAtUnixSeconds
    self.originalSessionID = originalSessionID
    self.target = target
    self.originalFailure = originalFailure
    basis = report.basis.rawValue
    outcome = report.outcome.rawValue
    failure = report.failure?.rawValue
    originalCleanupRestored = report.originalCleanupRestored
    permitsReconnect = report.permitsReconnect
    self.noActiveMaster = noActiveMaster
    mutationLeaseAcquired = report.mutationLeaseAcquired
    preflightSafe = report.preflightSafe
    authorizationClose = report.authorizationClose.rawValue
    authorizationOwnedMaterialErased = report.authorizationOwnedMaterialErased
    serverContactRequested = report.serverContactRequested
    captureAttemptCount = report.captureAttemptCount
    evidence = report.captureAssessment.map(UserProductRecoveryEvidenceReceipt.init)
    containsSecrets = report.containsSecrets
  }

  var valid: Bool {
    schemaVersion == 1 && UUID(uuidString: measurementID) != nil
      && measuredAtUnixSeconds > 0
      && UUID(uuidString: originalSessionID) != nil
      && ProductM2SSHTarget(rawValue: target) != nil
      && basis == "current_profile_cold_baseline"
      && !originalCleanupRestored && !containsSecrets
      && ProductM2AuthorizationCloseOutcome(rawValue: authorizationClose) != nil
      && (0...2).contains(captureAttemptCount)
      && (evidence?.valid ?? true)
      && (!permitsReconnect
        || (outcome == "recovered" && failure == nil && mutationLeaseAcquired
          && noActiveMaster
          && preflightSafe
          && authorizationClose == ProductM2AuthorizationCloseOutcome.accepted.rawValue
          && authorizationOwnedMaterialErased && captureAttemptCount == 2
          && evidence?.recomputedPassed == true))
  }
}

struct UserProductRecoveryArchive: Codable, Equatable, Sendable {
  let schemaVersion: Int
  let originalSessionID: String
  let target: String
  let originalCleanupVerified: Bool
  let originalFailure: String?
  let originalCleanupReceipt: UserProductOriginalCleanupReceipt?
  let recoveryReceipt: UserProductRecoveryReceipt
  let containsSecrets: Bool

  var valid: Bool {
    schemaVersion == 1 && UUID(uuidString: originalSessionID) != nil
      && ProductM2SSHTarget(rawValue: target) != nil
      && !originalCleanupVerified && !containsSecrets
      && recoveryReceipt.valid && recoveryReceipt.permitsReconnect
      && recoveryReceipt.originalSessionID == originalSessionID
      && recoveryReceipt.target == target
      && recoveryReceipt.originalFailure == originalFailure
      && (originalCleanupReceipt?.valid ?? true)
  }
}
