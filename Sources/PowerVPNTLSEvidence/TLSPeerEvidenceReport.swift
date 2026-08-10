import Foundation

public enum TLSPeerEvidenceStatus: String, Codable, Sendable {
  case observed
  case timedOut = "timed_out"
  case cancelled
  case unavailable
  case invalidEvidence = "invalid_evidence"
}

public enum TLSTrustCategory: String, Codable, Sendable {
  case accepted
  case hostnameMismatch = "hostname_mismatch"
  case expired
  case notYetValid = "not_yet_valid"
  case revoked
  case untrustedChain = "untrusted_chain"
  case otherFailure = "other_failure"
  case unavailable
}

public struct TLSPeerEvidenceReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let evidenceClass: String
  public let status: TLSPeerEvidenceStatus
  public let chainLength: Int
  public let orderedCertificateSHA256: [String]
  public let leafCertificateSHA256: String?
  public let leafSPKISHA256: String?
  public let sslTrustAccepted: Bool
  public let sslTrustCategory: TLSTrustCategory
  public let basicTrustAccepted: Bool
  public let basicTrustCategory: TLSTrustCategory
  public let transportProgress: TLSConnectionProgress
  public let evidenceProgress: TLSEvidenceProgress
  public let applicationDataSent: Bool
  public let verifyAccepted: Bool
  public let containsRawCertificate: Bool
  public let containsSubject: Bool
  public let containsIssuer: Bool
  public let containsSAN: Bool
  public let containsSerial: Bool
  public let containsSecrets: Bool

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion
    case evidenceClass
    case status
    case chainLength
    case orderedCertificateSHA256
    case leafCertificateSHA256
    case leafSPKISHA256
    case sslTrustAccepted
    case sslTrustCategory
    case basicTrustAccepted
    case basicTrustCategory
    case transportProgress
    case evidenceProgress
    case applicationDataSent
    case verifyAccepted
    case containsRawCertificate
    case containsSubject
    case containsIssuer
    case containsSAN
    case containsSerial
    case containsSecrets
  }

  init(
    snapshot: TLSTrustSnapshot,
    progress: TLSPeerProgressSnapshot
  ) {
    self.init(
      status: .observed,
      chainLength: snapshot.orderedCertificateSHA256.count,
      orderedCertificateSHA256: snapshot.orderedCertificateSHA256,
      leafCertificateSHA256: snapshot.orderedCertificateSHA256.first,
      leafSPKISHA256: snapshot.leafSPKISHA256,
      sslTrustAccepted: snapshot.sslTrust.accepted,
      sslTrustCategory: snapshot.sslTrust.category,
      basicTrustAccepted: snapshot.basicTrust.accepted,
      basicTrustCategory: snapshot.basicTrust.category,
      transportProgress: progress.transport,
      evidenceProgress: progress.evidence
    )
  }

  init(
    status: TLSPeerEvidenceStatus,
    progress: TLSPeerProgressSnapshot = TLSPeerProgressSnapshot()
  ) {
    self.init(
      status: status,
      chainLength: 0,
      orderedCertificateSHA256: [],
      leafCertificateSHA256: nil,
      leafSPKISHA256: nil,
      sslTrustAccepted: false,
      sslTrustCategory: .unavailable,
      basicTrustAccepted: false,
      basicTrustCategory: .unavailable,
      transportProgress: progress.transport,
      evidenceProgress: progress.evidence
    )
  }

  private init(
    status: TLSPeerEvidenceStatus,
    chainLength: Int,
    orderedCertificateSHA256: [String],
    leafCertificateSHA256: String?,
    leafSPKISHA256: String?,
    sslTrustAccepted: Bool,
    sslTrustCategory: TLSTrustCategory,
    basicTrustAccepted: Bool,
    basicTrustCategory: TLSTrustCategory,
    transportProgress: TLSConnectionProgress,
    evidenceProgress: TLSEvidenceProgress
  ) {
    schemaVersion = 3
    evidenceClass = "r2_tls_peer_value_free"
    self.status = status
    self.chainLength = chainLength
    self.orderedCertificateSHA256 = orderedCertificateSHA256
    self.leafCertificateSHA256 = leafCertificateSHA256
    self.leafSPKISHA256 = leafSPKISHA256
    self.sslTrustAccepted = sslTrustAccepted
    self.sslTrustCategory = sslTrustCategory
    self.basicTrustAccepted = basicTrustAccepted
    self.basicTrustCategory = basicTrustCategory
    self.transportProgress = transportProgress
    self.evidenceProgress = evidenceProgress
    applicationDataSent = false
    verifyAccepted = false
    containsRawCertificate = false
    containsSubject = false
    containsIssuer = false
    containsSAN = false
    containsSerial = false
    containsSecrets = false
  }

  public func encode(to encoder: any Encoder) throws {
    guard isValid else {
      throw EncodingError.invalidValue(
        self,
        .init(codingPath: encoder.codingPath, debugDescription: "invalid report invariant")
      )
    }
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(schemaVersion, forKey: .schemaVersion)
    try values.encode(evidenceClass, forKey: .evidenceClass)
    try values.encode(status, forKey: .status)
    try values.encode(chainLength, forKey: .chainLength)
    try values.encode(orderedCertificateSHA256, forKey: .orderedCertificateSHA256)
    if let leafCertificateSHA256 {
      try values.encode(leafCertificateSHA256, forKey: .leafCertificateSHA256)
    } else {
      try values.encodeNil(forKey: .leafCertificateSHA256)
    }
    if let leafSPKISHA256 {
      try values.encode(leafSPKISHA256, forKey: .leafSPKISHA256)
    } else {
      try values.encodeNil(forKey: .leafSPKISHA256)
    }
    try values.encode(sslTrustAccepted, forKey: .sslTrustAccepted)
    try values.encode(sslTrustCategory, forKey: .sslTrustCategory)
    try values.encode(basicTrustAccepted, forKey: .basicTrustAccepted)
    try values.encode(basicTrustCategory, forKey: .basicTrustCategory)
    try values.encode(transportProgress, forKey: .transportProgress)
    try values.encode(evidenceProgress, forKey: .evidenceProgress)
    try values.encode(applicationDataSent, forKey: .applicationDataSent)
    try values.encode(verifyAccepted, forKey: .verifyAccepted)
    try values.encode(containsRawCertificate, forKey: .containsRawCertificate)
    try values.encode(containsSubject, forKey: .containsSubject)
    try values.encode(containsIssuer, forKey: .containsIssuer)
    try values.encode(containsSAN, forKey: .containsSAN)
    try values.encode(containsSerial, forKey: .containsSerial)
    try values.encode(containsSecrets, forKey: .containsSecrets)
  }

  public init(from decoder: any Decoder) throws {
    let dynamic = try decoder.container(keyedBy: DynamicCodingKey.self)
    let expected = Set(CodingKeys.allCases.map(\.rawValue))
    guard Set(dynamic.allKeys.map(\.stringValue)) == expected else {
      throw DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: "unexpected report shape"))
    }
    let values = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try values.decode(Int.self, forKey: .schemaVersion)
    evidenceClass = try values.decode(String.self, forKey: .evidenceClass)
    status = try values.decode(TLSPeerEvidenceStatus.self, forKey: .status)
    chainLength = try values.decode(Int.self, forKey: .chainLength)
    orderedCertificateSHA256 = try values.decode(
      [String].self,
      forKey: .orderedCertificateSHA256
    )
    leafCertificateSHA256 = try values.decodeIfPresent(
      String.self,
      forKey: .leafCertificateSHA256
    )
    leafSPKISHA256 = try values.decodeIfPresent(String.self, forKey: .leafSPKISHA256)
    sslTrustAccepted = try values.decode(Bool.self, forKey: .sslTrustAccepted)
    sslTrustCategory = try values.decode(TLSTrustCategory.self, forKey: .sslTrustCategory)
    basicTrustAccepted = try values.decode(Bool.self, forKey: .basicTrustAccepted)
    basicTrustCategory = try values.decode(
      TLSTrustCategory.self,
      forKey: .basicTrustCategory
    )
    transportProgress = try values.decode(
      TLSConnectionProgress.self,
      forKey: .transportProgress
    )
    evidenceProgress = try values.decode(
      TLSEvidenceProgress.self,
      forKey: .evidenceProgress
    )
    applicationDataSent = try values.decode(Bool.self, forKey: .applicationDataSent)
    verifyAccepted = try values.decode(Bool.self, forKey: .verifyAccepted)
    containsRawCertificate = try values.decode(Bool.self, forKey: .containsRawCertificate)
    containsSubject = try values.decode(Bool.self, forKey: .containsSubject)
    containsIssuer = try values.decode(Bool.self, forKey: .containsIssuer)
    containsSAN = try values.decode(Bool.self, forKey: .containsSAN)
    containsSerial = try values.decode(Bool.self, forKey: .containsSerial)
    containsSecrets = try values.decode(Bool.self, forKey: .containsSecrets)
    guard isValid else {
      throw DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: "invalid report invariant"))
    }
  }

  private var isValid: Bool {
    guard schemaVersion == 3, evidenceClass == "r2_tls_peer_value_free",
      chainLength == orderedCertificateSHA256.count,
      TLSPeerProgressSnapshot(
        transport: transportProgress,
        evidence: evidenceProgress
      ).isValid,
      !applicationDataSent, !verifyAccepted, !containsRawCertificate,
      !containsSubject, !containsIssuer, !containsSAN, !containsSerial, !containsSecrets
    else { return false }
    if status == .observed {
      return transportProgress.verifyCallbackObserved && !transportProgress.readyObserved
        && evidenceProgress.transportEvidenceComplete
        && evidenceProgress.trustEvidenceComplete
        && chainLength > 0 && chainLength <= 16
        && leafCertificateSHA256 == orderedCertificateSHA256.first
        && orderedCertificateSHA256.allSatisfy(Self.isSHA256Hex)
        && leafSPKISHA256.map(Self.isSHA256Hex) == true
        && sslTrustAccepted == (sslTrustCategory == .accepted)
        && basicTrustAccepted == (basicTrustCategory == .accepted)
    }
    return (!transportProgress.readyObserved || status == .invalidEvidence)
      && !evidenceProgress.trustEvidenceComplete
      && chainLength == 0 && leafCertificateSHA256 == nil && leafSPKISHA256 == nil
      && !sslTrustAccepted && sslTrustCategory == .unavailable
      && !basicTrustAccepted && basicTrustCategory == .unavailable
  }

  private static func isSHA256Hex(_ value: String) -> Bool {
    value.utf8.count == 64
      && value.utf8.allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
      }
  }
}

private struct DynamicCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue _: Int) { nil }
}
