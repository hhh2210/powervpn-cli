import Foundation

public struct TLSEvidenceProgress: Codable, Equatable, Sendable {
  public let metadataChainAccessAttempted: Bool
  public let metadataChainAccessible: Bool
  public let peerDERCopyCompleted: Bool
  public let verifyCompletionInvokedWithFalse: Bool
  public let verifyCompletionReturned: Bool
  public let sslEvaluationStarted: Bool
  public let sslEvaluationCompleted: Bool
  public let basicEvaluationStarted: Bool
  public let basicEvaluationCompleted: Bool
  public let evaluationDeadlineExpired: Bool
  public let duplicateVerifyCallbackObserved: Bool
  public let transportEvidenceComplete: Bool
  public let trustEvidenceComplete: Bool

  enum CodingKeys: String, CodingKey, CaseIterable {
    case metadataChainAccessAttempted
    case metadataChainAccessible
    case peerDERCopyCompleted
    case verifyCompletionInvokedWithFalse
    case verifyCompletionReturned
    case sslEvaluationStarted
    case sslEvaluationCompleted
    case basicEvaluationStarted
    case basicEvaluationCompleted
    case evaluationDeadlineExpired
    case duplicateVerifyCallbackObserved
    case transportEvidenceComplete
    case trustEvidenceComplete
  }

  init(
    metadataChainAccessAttempted: Bool = false,
    metadataChainAccessible: Bool = false,
    peerDERCopyCompleted: Bool = false,
    verifyCompletionInvokedWithFalse: Bool = false,
    verifyCompletionReturned: Bool = false,
    sslEvaluationStarted: Bool = false,
    sslEvaluationCompleted: Bool = false,
    basicEvaluationStarted: Bool = false,
    basicEvaluationCompleted: Bool = false,
    evaluationDeadlineExpired: Bool = false,
    duplicateVerifyCallbackObserved: Bool = false
  ) {
    self.metadataChainAccessAttempted = metadataChainAccessAttempted
    self.metadataChainAccessible = metadataChainAccessible
    self.peerDERCopyCompleted = peerDERCopyCompleted
    self.verifyCompletionInvokedWithFalse = verifyCompletionInvokedWithFalse
    self.verifyCompletionReturned = verifyCompletionReturned
    self.sslEvaluationStarted = sslEvaluationStarted
    self.sslEvaluationCompleted = sslEvaluationCompleted
    self.basicEvaluationStarted = basicEvaluationStarted
    self.basicEvaluationCompleted = basicEvaluationCompleted
    self.evaluationDeadlineExpired = evaluationDeadlineExpired
    self.duplicateVerifyCallbackObserved = duplicateVerifyCallbackObserved
    transportEvidenceComplete =
      metadataChainAccessible && peerDERCopyCompleted
      && verifyCompletionReturned && !duplicateVerifyCallbackObserved
    trustEvidenceComplete =
      peerDERCopyCompleted && sslEvaluationCompleted
      && basicEvaluationCompleted && !evaluationDeadlineExpired
      && !duplicateVerifyCallbackObserved
  }

  public func encode(to encoder: any Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(metadataChainAccessAttempted, forKey: .metadataChainAccessAttempted)
    try values.encode(metadataChainAccessible, forKey: .metadataChainAccessible)
    try values.encode(peerDERCopyCompleted, forKey: .peerDERCopyCompleted)
    try values.encode(
      verifyCompletionInvokedWithFalse,
      forKey: .verifyCompletionInvokedWithFalse
    )
    try values.encode(verifyCompletionReturned, forKey: .verifyCompletionReturned)
    try values.encode(sslEvaluationStarted, forKey: .sslEvaluationStarted)
    try values.encode(sslEvaluationCompleted, forKey: .sslEvaluationCompleted)
    try values.encode(basicEvaluationStarted, forKey: .basicEvaluationStarted)
    try values.encode(basicEvaluationCompleted, forKey: .basicEvaluationCompleted)
    try values.encode(evaluationDeadlineExpired, forKey: .evaluationDeadlineExpired)
    try values.encode(
      duplicateVerifyCallbackObserved,
      forKey: .duplicateVerifyCallbackObserved
    )
    try values.encode(transportEvidenceComplete, forKey: .transportEvidenceComplete)
    try values.encode(trustEvidenceComplete, forKey: .trustEvidenceComplete)
  }

  public init(from decoder: any Decoder) throws {
    let dynamic = try decoder.container(keyedBy: EvidenceProgressCodingKey.self)
    let expected = Set(CodingKeys.allCases.map(\.rawValue))
    guard Set(dynamic.allKeys.map(\.stringValue)) == expected else {
      throw DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: "unexpected evidence shape"))
    }
    let values = try decoder.container(keyedBy: CodingKeys.self)
    metadataChainAccessAttempted = try values.decode(
      Bool.self,
      forKey: .metadataChainAccessAttempted
    )
    metadataChainAccessible = try values.decode(Bool.self, forKey: .metadataChainAccessible)
    peerDERCopyCompleted = try values.decode(Bool.self, forKey: .peerDERCopyCompleted)
    verifyCompletionInvokedWithFalse = try values.decode(
      Bool.self,
      forKey: .verifyCompletionInvokedWithFalse
    )
    verifyCompletionReturned = try values.decode(Bool.self, forKey: .verifyCompletionReturned)
    sslEvaluationStarted = try values.decode(Bool.self, forKey: .sslEvaluationStarted)
    sslEvaluationCompleted = try values.decode(Bool.self, forKey: .sslEvaluationCompleted)
    basicEvaluationStarted = try values.decode(Bool.self, forKey: .basicEvaluationStarted)
    basicEvaluationCompleted = try values.decode(Bool.self, forKey: .basicEvaluationCompleted)
    evaluationDeadlineExpired = try values.decode(
      Bool.self,
      forKey: .evaluationDeadlineExpired
    )
    duplicateVerifyCallbackObserved = try values.decode(
      Bool.self,
      forKey: .duplicateVerifyCallbackObserved
    )
    transportEvidenceComplete = try values.decode(
      Bool.self,
      forKey: .transportEvidenceComplete
    )
    trustEvidenceComplete = try values.decode(Bool.self, forKey: .trustEvidenceComplete)
    guard isValid else {
      throw DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: "invalid evidence invariant"))
    }
  }

  var isValid: Bool {
    guard !metadataChainAccessible || metadataChainAccessAttempted,
      !peerDERCopyCompleted || metadataChainAccessible,
      !verifyCompletionReturned || verifyCompletionInvokedWithFalse,
      !sslEvaluationStarted || (peerDERCopyCompleted && verifyCompletionReturned),
      !basicEvaluationStarted || (peerDERCopyCompleted && verifyCompletionReturned),
      !sslEvaluationCompleted || sslEvaluationStarted,
      !basicEvaluationCompleted || basicEvaluationStarted,
      !evaluationDeadlineExpired || (sslEvaluationStarted || basicEvaluationStarted),
      transportEvidenceComplete
        == (metadataChainAccessible && peerDERCopyCompleted && verifyCompletionReturned
          && !duplicateVerifyCallbackObserved),
      trustEvidenceComplete
        == (peerDERCopyCompleted && sslEvaluationCompleted && basicEvaluationCompleted
          && !evaluationDeadlineExpired && !duplicateVerifyCallbackObserved)
    else { return false }
    return true
  }
}

enum TLSTrustEvaluationPhase: Sendable {
  case sslStarted
  case sslCompleted
  case basicStarted
  case basicCompleted
  case deadlineExpired
}

private struct EvidenceProgressCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil
  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue _: Int) { nil }
}
