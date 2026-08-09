import Foundation

public enum VendorXPCProbeStatus: String, Codable, Sendable {
  case accepted
  case preflightBlocked = "preflight_blocked"
  case transportFailed = "transport_failed"
}

public struct VendorXPCR1SafetyEvidence: Encodable, Equatable, Sendable {
  public let loginRequested = false
  public let serverContactRequested = false
  public let startConnectionRequested = false
  public let routeMutationRequested = false
  public let saMutationRequested = false
  public let utunMutationRequested = false
  public let rawXPCSerialized = false
  public let containsSecrets = false

  public init() {}
}

public struct VendorXPCProbeReport: Encodable, Equatable, Sendable {
  public let schemaVersion = 1
  public let evidenceClass = "read_only_vendor_charon_get_version"
  public let mode = "cold_start_exact_xpc"
  public let status: VendorXPCProbeStatus
  public let transportOutcome: VendorXPCGetVersionOutcome?
  public let exactReplySchema: Bool
  public let versionByteLength: Int?
  public let versionMatchesLockedBuild: Bool
  public let getVersionSuccess: Bool
  public let emptyDispatcherTailObserved: Bool
  public let emptyReplyAcknowledgementObserved: Bool
  public let helperGenerationRelation: VendorHelperGenerationRelation
  public let replyPeerMatchesObservedGeneration: Bool
  public let connectionCancelRequested: Bool
  public let preflight: VendorXPCPreflightEvidence
  public let safety = VendorXPCR1SafetyEvidence()
  public let transactionAccepted: Bool

  public init(
    status: VendorXPCProbeStatus,
    transportOutcome: VendorXPCGetVersionOutcome?,
    exactReplySchema: Bool,
    versionByteLength: Int?,
    versionMatchesLockedBuild: Bool,
    getVersionSuccess: Bool,
    emptyDispatcherTailObserved: Bool,
    emptyReplyAcknowledgementObserved: Bool,
    helperGenerationRelation: VendorHelperGenerationRelation,
    replyPeerMatchesObservedGeneration: Bool,
    connectionCancelRequested: Bool,
    preflight: VendorXPCPreflightEvidence,
    transactionAccepted: Bool
  ) {
    self.status = status
    self.transportOutcome = transportOutcome
    self.exactReplySchema = exactReplySchema
    self.versionByteLength = versionByteLength
    self.versionMatchesLockedBuild = versionMatchesLockedBuild
    self.getVersionSuccess = getVersionSuccess
    self.emptyDispatcherTailObserved = emptyDispatcherTailObserved
    self.emptyReplyAcknowledgementObserved = emptyReplyAcknowledgementObserved
    self.helperGenerationRelation = helperGenerationRelation
    self.replyPeerMatchesObservedGeneration = replyPeerMatchesObservedGeneration
    self.connectionCancelRequested = connectionCancelRequested
    self.preflight = preflight
    self.transactionAccepted = transactionAccepted
  }
}

public struct VendorXPCProbe: Sendable {
  private let transport: any VendorXPCTransporting
  private let generationObserver: any VendorHelperGenerationObserving
  private let preflightChecker: any VendorXPCPreflightChecking

  public init(
    transport: any VendorXPCTransporting = RawVendorXPCTransport(),
    generationObserver: any VendorHelperGenerationObserving =
      LaunchdVendorHelperGenerationObserver(),
    preflightChecker: any VendorXPCPreflightChecking = InstalledVendorXPCPreflightChecker()
  ) {
    self.transport = transport
    self.generationObserver = generationObserver
    self.preflightChecker = preflightChecker
  }

  public func getVersion(timeoutMilliseconds: Int) async -> VendorXPCProbeReport {
    let before = generationObserver.observe()
    let preflight = preflightChecker.check(generation: before)
    guard preflight.safeToProbe else {
      return VendorXPCProbeReport(
        status: .preflightBlocked,
        transportOutcome: nil,
        exactReplySchema: false,
        versionByteLength: nil,
        versionMatchesLockedBuild: false,
        getVersionSuccess: false,
        emptyDispatcherTailObserved: false,
        emptyReplyAcknowledgementObserved: false,
        helperGenerationRelation: before.inactiveConfirmed
          ? .inactive : .unavailable,
        replyPeerMatchesObservedGeneration: false,
        connectionCancelRequested: false,
        preflight: preflight,
        transactionAccepted: false
      )
    }

    let evidence = await transport.getVersion(
      timeoutMilliseconds: timeoutMilliseconds
    ) { peerPID in
      VendorReplyGenerationValidator.validate(
        before: before,
        current: generationObserver.observe(),
        peerPID: peerPID
      )
    }
    let after = generationObserver.observe()
    let generation = VendorHelperGenerationAssessment.assess(
      before: before,
      after: after,
      replyPeerGenerationValidated: evidence.replyPeerGenerationValidated
    )
    let generationAccepted =
      generation.relation == .launched
      || generation.relation == .launchedAndExited
    let accepted =
      evidence.accepted
      && generationAccepted
      && generation.replyPeerMatchesObservedGeneration
      && evidence.connectionCancelRequested

    let exactReplySchema =
      evidence.outcome == .accepted
      || evidence.outcome == .lockedVersionMismatch
      || evidence.outcome == .getVersionRejected
    return VendorXPCProbeReport(
      status: accepted ? .accepted : .transportFailed,
      transportOutcome: evidence.outcome,
      exactReplySchema: exactReplySchema,
      versionByteLength: evidence.versionByteLength,
      versionMatchesLockedBuild: evidence.versionMatchesLockedBuild,
      getVersionSuccess: evidence.getVersionSuccess,
      emptyDispatcherTailObserved: evidence.emptyDispatcherTailObserved,
      emptyReplyAcknowledgementObserved: evidence.emptyReplyAcknowledgementObserved,
      helperGenerationRelation: generation.relation,
      replyPeerMatchesObservedGeneration: generation.replyPeerMatchesObservedGeneration,
      connectionCancelRequested: evidence.connectionCancelRequested,
      preflight: preflight,
      transactionAccepted: accepted
    )
  }
}

enum VendorReplyGenerationValidator {
  static func validate(
    before: VendorHelperGenerationSnapshot,
    current: VendorHelperGenerationSnapshot,
    peerPID: Int32
  ) -> Bool {
    guard before.exactInactive, current.exactRunning,
      peerPID > 0, current.pid == Int(peerPID),
      let beforeRuns = before.runs, beforeRuns < Int.max,
      current.runs == beforeRuns + 1
    else { return false }
    return true
  }
}
