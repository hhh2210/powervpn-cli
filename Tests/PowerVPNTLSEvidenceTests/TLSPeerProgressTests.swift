import Foundation
import Testing

@testable import PowerVPNTLSEvidence

@Suite struct TLSPeerProgressTests {
  @Test func atomicVerifyEntryNeverExposesCrossObjectSkew() {
    for _ in 0..<128 {
      let recorder = TLSPeerProgressRecorder()
      recorder.recordConnectionStarted()
      let start = DispatchSemaphore(value: 0)
      let done = DispatchSemaphore(value: 0)
      DispatchQueue.global().async {
        start.wait()
        recorder.recordVerifyEntry(isDuplicate: false)
        done.signal()
      }

      start.signal()
      #expect(recorder.snapshot().isValid)
      #expect(done.wait(timeout: .now() + .seconds(2)) == .success)
      let completed = recorder.snapshot()
      #expect(completed.isValid)
      #expect(completed.transport.verifyCallbackObserved)
      #expect(completed.evidence.metadataChainAccessAttempted)
    }
  }

  @Test func duplicateEntryAtomicallyCarriesActiveCallbackEvidence() {
    let recorder = TLSPeerProgressRecorder()
    recorder.recordConnectionStarted()
    recorder.recordVerifyEntry(isDuplicate: true)
    let snapshot = recorder.snapshot()
    #expect(snapshot.isValid)
    #expect(snapshot.transport.verifyCallbackObserved)
    #expect(snapshot.evidence.duplicateVerifyCallbackObserved)
  }

  @Test func independentlyConstructedSkewFailsClosed() {
    let skewed = TLSPeerProgressSnapshot(
      transport: TLSConnectionProgress(connectionStarted: true),
      evidence: TLSEvidenceProgress(metadataChainAccessAttempted: true)
    )
    #expect(!skewed.isValid)
  }
}
