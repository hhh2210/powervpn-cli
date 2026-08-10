import Foundation

public enum TLSPeerEvidenceRuntime {
  static let sealedTimeoutNanoseconds: UInt64 = 15_000_000_000

  public static func observeSealedEndpoint() async -> TLSPeerEvidenceReport {
    await TLSPeerObserver(
      source: NetworkTLSTrustSource(),
      timeoutNanoseconds: sealedTimeoutNanoseconds
    ).observe()
  }
}

struct TLSPeerObserver: Sendable {
  let source: any TLSTrustSource
  let timeoutNanoseconds: UInt64

  func observe() async -> TLSPeerEvidenceReport {
    let session = TLSPeerObservationSession(
      source: source,
      timeoutNanoseconds: timeoutNanoseconds
    )
    return await withTaskCancellationHandler {
      await session.run()
    } onCancel: {
      session.cancel()
    }
  }
}

private final class TLSPeerObservationSession: @unchecked Sendable {
  private let source: any TLSTrustSource
  private let timeoutNanoseconds: UInt64
  private let lock = NSLock()
  private var continuation: CheckedContinuation<TLSPeerEvidenceReport, Never>?
  private var terminalReport: TLSPeerEvidenceReport?
  private var timeoutTask: Task<Void, Never>?
  private var started = false

  init(source: any TLSTrustSource, timeoutNanoseconds: UInt64) {
    self.source = source
    self.timeoutNanoseconds = timeoutNanoseconds
  }

  func run() async -> TLSPeerEvidenceReport {
    await withCheckedContinuation { continuation in
      let state = lock.withLock { () -> (TLSPeerEvidenceReport?, Bool) in
        if let terminalReport { return (terminalReport, false) }
        guard !started else {
          return (
            TLSPeerEvidenceReport(
              status: .invalidEvidence,
              progress: source.progressSnapshot()
            ),
            false
          )
        }
        started = true
        self.continuation = continuation
        return (nil, true)
      }
      if let report = state.0 {
        continuation.resume(returning: report)
        return
      }
      guard state.1 else {
        continuation.resume(
          returning: TLSPeerEvidenceReport(
            status: .invalidEvidence,
            progress: source.progressSnapshot()
          ))
        return
      }
      source.start { [weak self] event in self?.receive(event) }
      let timeout = Task { [weak self, timeoutNanoseconds] in
        do {
          try await Task.sleep(nanoseconds: timeoutNanoseconds)
        } catch {
          return
        }
        self?.finish(
          TLSPeerEvidenceReport(
            status: .timedOut,
            progress: self?.source.progressSnapshot() ?? TLSPeerProgressSnapshot()
          ))
      }
      let cancelTimeout = lock.withLock {
        if terminalReport == nil {
          timeoutTask = timeout
          return false
        }
        return true
      }
      if cancelTimeout { timeout.cancel() }
    }
  }

  func cancel() {
    finish(
      TLSPeerEvidenceReport(
        status: .cancelled,
        progress: source.progressSnapshot()
      ))
  }

  private func receive(_ event: TLSTrustSourceEvent) {
    switch event {
    case .captured(let snapshot):
      finish(
        TLSPeerEvidenceReport(
          snapshot: snapshot,
          progress: source.progressSnapshot()
        ))
    case .timedOut:
      finish(
        TLSPeerEvidenceReport(
          status: .timedOut,
          progress: source.progressSnapshot()
        ))
    case .invalidEvidence:
      finish(
        TLSPeerEvidenceReport(
          status: .invalidEvidence,
          progress: source.progressSnapshot()
        ))
    case .unavailable:
      finish(
        TLSPeerEvidenceReport(
          status: .unavailable,
          progress: source.progressSnapshot()
        ))
    }
  }

  private func finish(_ report: TLSPeerEvidenceReport) {
    let state = lock.withLock {
      () -> (
        CheckedContinuation<TLSPeerEvidenceReport, Never>?, Task<Void, Never>?
      ) in
      guard terminalReport == nil else { return (nil, nil) }
      terminalReport = report
      let retainedContinuation = continuation
      continuation = nil
      let retainedTimeout = timeoutTask
      timeoutTask = nil
      return (retainedContinuation, retainedTimeout)
    }
    state.1?.cancel()
    source.cancel()
    state.0?.resume(returning: report)
  }
}
