import Foundation

@testable import PowerVPNCore

actor ProbeGenerationObserver: BoundedVendorHelperGenerationObserving {
  private var snapshots: [VendorHelperGenerationSnapshot]
  private(set) var callCount = 0

  init(_ snapshots: [VendorHelperGenerationSnapshot]) {
    self.snapshots = snapshots
  }

  func observe(
    timeoutMilliseconds _: Int
  ) async -> VendorHelperGenerationSnapshot {
    callCount += 1
    if snapshots.count > 1 { return snapshots.removeFirst() }
    return snapshots[0]
  }
}

actor ProbePreflightChecker: BoundedVendorXPCPreflightChecking {
  private let evidence: VendorXPCPreflightEvidence
  private(set) var callCount = 0

  init(_ evidence: VendorXPCPreflightEvidence) {
    self.evidence = evidence
  }

  func check(
    generation _: VendorHelperGenerationSnapshot,
    timeoutMilliseconds _: Int
  ) async -> VendorXPCPreflightEvidence {
    callCount += 1
    return evidence
  }
}

actor ProbeTransport: VendorXPCTransporting {
  private let evidence: VendorXPCGetVersionEvidence
  private let peerPID: Int32?
  private(set) var callCount = 0

  init(evidence: VendorXPCGetVersionEvidence, peerPID: Int32?) {
    self.evidence = evidence
    self.peerPID = peerPID
  }

  func getVersion(
    timeoutMilliseconds _: Int,
    peerGenerationValidator: @escaping @Sendable (Int32) async -> Bool
  ) async -> VendorXPCGetVersionEvidence {
    callCount += 1
    let peerValidated: Bool
    if let peerPID {
      peerValidated = await peerGenerationValidator(peerPID)
    } else {
      peerValidated = evidence.replyPeerGenerationValidated
    }
    return VendorXPCGetVersionEvidence(
      outcome: evidence.outcome,
      versionByteLength: evidence.versionByteLength,
      versionMatchesLockedBuild: evidence.versionMatchesLockedBuild,
      getVersionSuccess: evidence.getVersionSuccess,
      emptyDispatcherTailObserved: evidence.emptyDispatcherTailObserved,
      emptyReplyAcknowledgementObserved: evidence.emptyReplyAcknowledgementObserved,
      replyPeerGenerationValidated: peerValidated,
      connectionCancelRequested: evidence.connectionCancelRequested
    )
  }
}

actor CancellableProbeTransport: VendorXPCTransporting {
  private var started = false
  private var startWaiters: [CheckedContinuation<Void, Never>] = []

  func getVersion(
    timeoutMilliseconds _: Int,
    peerGenerationValidator _: @escaping @Sendable (Int32) async -> Bool
  ) async -> VendorXPCGetVersionEvidence {
    started = true
    let current = startWaiters
    startWaiters.removeAll()
    for waiter in current { waiter.resume() }
    while !Task.isCancelled {
      try? await Task.sleep(for: .milliseconds(1))
    }
    return VendorXPCGetVersionEvidence(
      outcome: .cancelled,
      connectionCancelRequested: true
    )
  }

  func waitUntilStarted() async {
    guard !started else { return }
    await withCheckedContinuation { startWaiters.append($0) }
  }
}

actor ProbeGate {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    guard !released else { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func release() {
    released = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}
