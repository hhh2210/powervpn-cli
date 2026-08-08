import Foundation

enum StrictProtocolCorrelationDecoder {
  private static let rootKeys: Set<String> = [
    "schemaVersion", "fixtureClass", "redactionMode", "source", "containsSecrets",
    "containsReplayableCapture", "events",
  ]
  private static let requiredEventKeys: Set<String> = [
    "sequence", "boundary", "transport", "direction", "kind", "operation",
    "evidenceClass", "confidence", "fields", "transitions",
  ]
  private static let optionalEventKeys: Set<String> = [
    "relativeMilliseconds", "helperFamily", "method", "pathTemplate", "statusCode",
    "resultClass",
  ]
  private static let requiredFieldKeys: Set<String> = [
    "name", "type", "order", "evidenceClass", "confidence",
  ]
  private static let optionalFieldKeys: Set<String> = ["length", "lengthUnit"]
  private static let transitionKeys: Set<String> = [
    "domain", "from", "to", "trigger", "evidenceClass", "confidence",
  ]

  static func decode(_ data: Data) throws -> ProtocolCorrelationDocument {
    let object = try JSONSerialization.jsonObject(with: data)
    guard let root = object as? [String: Any], Set(root.keys) == rootKeys,
      let events = root["events"] as? [[String: Any]],
      events.allSatisfy({ event in
        ClosedJSONShape.hasOnlyAllowedKeys(
          event,
          required: requiredEventKeys,
          optional: optionalEventKeys
        )
          && (event["fields"] as? [[String: Any]])?.allSatisfy({
            ClosedJSONShape.hasOnlyAllowedKeys(
              $0,
              required: requiredFieldKeys,
              optional: optionalFieldKeys
            )
          }) == true
          && (event["transitions"] as? [[String: Any]])?.allSatisfy({
            Set($0.keys) == transitionKeys
          }) == true
      })
    else { throw ProtocolCorrelationDecodingError.invalidShape }
    return try JSONDecoder().decode(ProtocolCorrelationDocument.self, from: data)
  }
}

private enum ProtocolCorrelationDecodingError: Error {
  case invalidShape
}
