import Foundation
import Security
import Testing

@testable import PowerVPNTLSEvidence

@Suite struct TLSTrustSnapshotTests {
  @Test func selfSignedChainProducesOnlyHashesAndClosedTrustCategories() throws {
    let certificateDER = try fixtureDER("rsa-cert")
    let assessment = TLSTrustAssessment(accepted: false, category: .untrustedChain)
    let result = TLSTrustSnapshotBuilder.make(
      chain: TLSPeerCertificateChain(certificateDER: [certificateDER]),
      sslTrust: assessment,
      basicTrust: assessment
    )
    let snapshot: TLSTrustSnapshot
    switch result {
    case .success(let value): snapshot = value
    case .failure(let error):
      Issue.record("unexpected snapshot failure: \(error)")
      return
    }
    #expect(
      snapshot.orderedCertificateSHA256 == [
        "274e8cf9b4d2876c7f62be79ad49de327096c65dbd63d24c16886123985c42b9"
      ])
    #expect(
      snapshot.leafSPKISHA256
        == "c185e9fb0d89e34478d4622694489592f54458eb7560b0914f13c1f0c01fec19")
    #expect(!snapshot.sslTrust.accepted)
    #expect(!snapshot.basicTrust.accepted)
    #expect(snapshot.sslTrust.category != .accepted)
    #expect(snapshot.basicTrust.category != .accepted)
  }

  @Test func encodedReportHasExactValueFreeShapeAndRejectsExtensions() throws {
    let snapshot = TLSTrustSnapshot(
      orderedCertificateSHA256: [String(repeating: "a", count: 64)],
      leafSPKISHA256: String(repeating: "b", count: 64),
      sslTrust: TLSTrustAssessment(accepted: false, category: .untrustedChain),
      basicTrust: TLSTrustAssessment(accepted: false, category: .untrustedChain)
    )
    let progress = TLSConnectionProgress(
      connectionStarted: true,
      preparingObserved: true,
      verifyCallbackObserved: true
    )
    let evidenceProgress = completeEvidenceProgress()
    let report = TLSPeerEvidenceReport(
      snapshot: snapshot,
      progress: TLSPeerProgressSnapshot(
        transport: progress,
        evidence: evidenceProgress
      )
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(report)
    let text = try #require(String(data: data, encoding: .utf8))
    #expect(!text.contains("localhost"))
    #expect(!text.contains("BEGIN CERTIFICATE"))
    #expect(try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: data) == report)

    var object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(Set(object.keys) == Set(TLSPeerEvidenceReport.CodingKeys.allCases.map(\.rawValue)))
    #expect(object["applicationDataSent"] as? Bool == false)
    #expect(object["verifyAccepted"] as? Bool == false)
    #expect(object["containsRawCertificate"] as? Bool == false)
    #expect(object["containsSecrets"] as? Bool == false)
    #expect(object["schemaVersion"] as? Int == 3)
    let encodedProgress = try #require(object["transportProgress"] as? [String: Any])
    #expect(
      Set(encodedProgress.keys)
        == Set(TLSConnectionProgress.CodingKeys.allCases.map(\.rawValue)))
    let encodedEvidence = try #require(object["evidenceProgress"] as? [String: Any])
    #expect(
      Set(encodedEvidence.keys)
        == Set(TLSEvidenceProgress.CodingKeys.allCases.map(\.rawValue)))

    object["unexpected"] = true
    let extended = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: extended)
    }
    object.removeValue(forKey: "unexpected")
    object["applicationDataSent"] = true
    let unsafe = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: unsafe)
    }
    object["applicationDataSent"] = false
    object["leafSPKISHA256"] = String(repeating: "G", count: 64)
    let nonHexDigest = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: nonHexDigest)
    }
    object["leafSPKISHA256"] = String(repeating: "b", count: 64)
    object["sslTrustAccepted"] = true
    let contradictoryTrust = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: contradictoryTrust)
    }

    object["sslTrustAccepted"] = false
    object["chainLength"] = 17
    object["orderedCertificateSHA256"] = Array(
      repeating: String(repeating: "a", count: 64),
      count: 17
    )
    let oversizedChain = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: oversizedChain)
    }
    object["chainLength"] = 1
    object["orderedCertificateSHA256"] = [String(repeating: "a", count: 64)]
    var nested = encodedProgress
    nested["unexpected"] = true
    object["transportProgress"] = nested
    let extendedProgress = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: extendedProgress)
    }

    object["transportProgress"] = encodedProgress
    var invalidEvidence = encodedEvidence
    invalidEvidence["transportEvidenceComplete"] = false
    object["evidenceProgress"] = invalidEvidence
    let overstatedPhase = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: overstatedPhase)
    }
    invalidEvidence = encodedEvidence
    invalidEvidence["verifyCompletionReturned"] = false
    object["evidenceProgress"] = invalidEvidence
    let incompleteVerify = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: incompleteVerify)
    }

    object["evidenceProgress"] = encodedEvidence
    var skewedTransport = encodedProgress
    skewedTransport["verifyCallbackObserved"] = false
    object["transportProgress"] = skewedTransport
    let skewedProgress = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: skewedProgress)
    }

    object["transportProgress"] = encodedProgress
    object["evidenceProgress"] = encodedEvidence
    object.removeValue(forKey: "evidenceProgress")
    object["schemaVersion"] = 2
    let legacyV2Shape = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: DecodingError.self) {
      _ = try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: legacyV2Shape)
    }
  }

  @Test func everyNonObservedTerminalReportRoundTripsWithExplicitNulls() throws {
    for status in [
      TLSPeerEvidenceStatus.timedOut,
      .cancelled,
      .unavailable,
      .invalidEvidence,
    ] {
      let report = TLSPeerEvidenceReport(status: status)
      let data = try JSONEncoder().encode(report)
      let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
      #expect(Set(object.keys) == Set(TLSPeerEvidenceReport.CodingKeys.allCases.map(\.rawValue)))
      #expect(object["leafCertificateSHA256"] is NSNull)
      #expect(object["leafSPKISHA256"] is NSNull)
      #expect(object["schemaVersion"] as? Int == 3)
      #expect(try JSONDecoder().decode(TLSPeerEvidenceReport.self, from: data) == report)
    }

    let transportOnly = TLSEvidenceProgress(
      metadataChainAccessAttempted: true,
      metadataChainAccessible: true,
      peerDERCopyCompleted: true,
      verifyCompletionInvokedWithFalse: true,
      verifyCompletionReturned: true
    )
    #expect(transportOnly.transportEvidenceComplete)
    #expect(!transportOnly.trustEvidenceComplete)
    let impossibleTransportCompleteTimeout = TLSPeerEvidenceReport(
      status: .timedOut,
      progress: TLSPeerProgressSnapshot(evidence: transportOnly)
    )
    #expect(throws: EncodingError.self) {
      _ = try JSONEncoder().encode(impossibleTransportCompleteTimeout)
    }

    let transportCompleteTimeout = TLSPeerEvidenceReport(
      status: .timedOut,
      progress: TLSPeerProgressSnapshot(
        transport: TLSConnectionProgress(
          connectionStarted: true,
          verifyCallbackObserved: true
        ),
        evidence: transportOnly
      )
    )
    let transportCompleteData = try JSONEncoder().encode(transportCompleteTimeout)
    #expect(
      try JSONDecoder().decode(
        TLSPeerEvidenceReport.self,
        from: transportCompleteData
      ) == transportCompleteTimeout)

    let duplicateWithoutTransport = TLSPeerEvidenceReport(
      status: .invalidEvidence,
      progress: TLSPeerProgressSnapshot(
        evidence: TLSEvidenceProgress(duplicateVerifyCallbackObserved: true)
      )
    )
    #expect(throws: EncodingError.self) {
      _ = try JSONEncoder().encode(duplicateWithoutTransport)
    }

    let impossibleCompleteTrust = TLSPeerEvidenceReport(
      status: .timedOut,
      progress: TLSPeerProgressSnapshot(
        transport: TLSConnectionProgress(
          connectionStarted: true,
          verifyCallbackObserved: true
        ),
        evidence: completeEvidenceProgress()
      )
    )
    #expect(throws: EncodingError.self) {
      _ = try JSONEncoder().encode(impossibleCompleteTrust)
    }

    let lateCompletion = TLSEvidenceProgress(
      verifyCompletionInvokedWithFalse: true,
      verifyCompletionReturned: true
    )
    let lateCompletionReport = TLSPeerEvidenceReport(
      status: .cancelled,
      progress: TLSPeerProgressSnapshot(evidence: lateCompletion)
    )
    let lateCompletionData = try JSONEncoder().encode(lateCompletionReport)
    #expect(
      try JSONDecoder().decode(
        TLSPeerEvidenceReport.self,
        from: lateCompletionData
      ) == lateCompletionReport)
  }

  private func completeEvidenceProgress() -> TLSEvidenceProgress {
    TLSEvidenceProgress(
      metadataChainAccessAttempted: true,
      metadataChainAccessible: true,
      peerDERCopyCompleted: true,
      verifyCompletionInvokedWithFalse: true,
      verifyCompletionReturned: true,
      sslEvaluationStarted: true,
      sslEvaluationCompleted: true,
      basicEvaluationStarted: true,
      basicEvaluationCompleted: true
    )
  }
}
