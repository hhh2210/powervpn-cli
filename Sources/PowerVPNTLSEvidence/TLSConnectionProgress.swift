import Foundation

public struct TLSConnectionProgress: Codable, Equatable, Sendable {
  public let connectionStarted: Bool
  public let preparingObserved: Bool
  public let waitingObserved: Bool
  public let verifyCallbackObserved: Bool
  public let failedObserved: Bool
  public let readyObserved: Bool

  enum CodingKeys: String, CodingKey, CaseIterable {
    case connectionStarted
    case preparingObserved
    case waitingObserved
    case verifyCallbackObserved
    case failedObserved
    case readyObserved
  }

  init(
    connectionStarted: Bool = false,
    preparingObserved: Bool = false,
    waitingObserved: Bool = false,
    verifyCallbackObserved: Bool = false,
    failedObserved: Bool = false,
    readyObserved: Bool = false
  ) {
    self.connectionStarted = connectionStarted
    self.preparingObserved = preparingObserved
    self.waitingObserved = waitingObserved
    self.verifyCallbackObserved = verifyCallbackObserved
    self.failedObserved = failedObserved
    self.readyObserved = readyObserved
  }

  public func encode(to encoder: any Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(connectionStarted, forKey: .connectionStarted)
    try values.encode(preparingObserved, forKey: .preparingObserved)
    try values.encode(waitingObserved, forKey: .waitingObserved)
    try values.encode(verifyCallbackObserved, forKey: .verifyCallbackObserved)
    try values.encode(failedObserved, forKey: .failedObserved)
    try values.encode(readyObserved, forKey: .readyObserved)
  }

  public init(from decoder: any Decoder) throws {
    let dynamic = try decoder.container(keyedBy: ProgressCodingKey.self)
    let expected = Set(CodingKeys.allCases.map(\.rawValue))
    guard Set(dynamic.allKeys.map(\.stringValue)) == expected else {
      throw DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: "unexpected progress shape"))
    }
    let values = try decoder.container(keyedBy: CodingKeys.self)
    connectionStarted = try values.decode(Bool.self, forKey: .connectionStarted)
    preparingObserved = try values.decode(Bool.self, forKey: .preparingObserved)
    waitingObserved = try values.decode(Bool.self, forKey: .waitingObserved)
    verifyCallbackObserved = try values.decode(Bool.self, forKey: .verifyCallbackObserved)
    failedObserved = try values.decode(Bool.self, forKey: .failedObserved)
    readyObserved = try values.decode(Bool.self, forKey: .readyObserved)
    guard isValid else {
      throw DecodingError.dataCorrupted(
        .init(codingPath: decoder.codingPath, debugDescription: "invalid progress invariant"))
    }
  }

  var isValid: Bool {
    guard !readyObserved || !failedObserved else { return false }
    return connectionStarted
      || !(preparingObserved || waitingObserved || verifyCallbackObserved
        || failedObserved || readyObserved)
  }
}

private struct ProgressCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue _: Int) { nil }
}
