import Foundation

public struct ProtocolCorrelationValidationIssue: Codable, Equatable, Sendable {
  public let path: String
  public let code: String
  public let message: String

  public init(path: String, code: String, message: String) {
    self.path = path
    self.code = code
    self.message = message
  }
}

public struct ProtocolCorrelationValidationReport: Codable, Equatable, Sendable {
  public let mode: String
  public let valid: Bool
  public let issues: [ProtocolCorrelationValidationIssue]

  public init(issues: [ProtocolCorrelationValidationIssue]) {
    mode = "metadata_only_protocol_correlation"
    valid = issues.isEmpty
    self.issues = issues
  }
}

public enum ProtocolCorrelationRedactedValidator {
  public static let maximumDocumentBytes = 1_048_576

  private static let maximumEvents = 2_048
  private static let maximumFieldsPerEvent = 256
  private static let maximumTransitionsPerEvent = 8
  private static let maximumObservedLength = 16_777_216

  public static func validate(contentsOf url: URL) throws -> ProtocolCorrelationValidationReport {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    let data = try handle.read(upToCount: maximumDocumentBytes + 1) ?? Data()
    return validate(data: data)
  }

  public static func validate(data: Data) -> ProtocolCorrelationValidationReport {
    guard data.count <= maximumDocumentBytes else {
      return ProtocolCorrelationValidationReport(issues: [
        issue("$", "size_limit", "document exceeds the metadata-only size limit")
      ])
    }
    do {
      return validate(try StrictProtocolCorrelationDecoder.decode(data))
    } catch {
      return ProtocolCorrelationValidationReport(issues: [
        issue("$", "invalid_schema", "document does not match the closed correlation schema")
      ])
    }
  }

  public static func validate(
    _ document: ProtocolCorrelationDocument
  ) -> ProtocolCorrelationValidationReport {
    var issues: [ProtocolCorrelationValidationIssue] = []
    if document.schemaVersion != 1 {
      issues.append(issue("schemaVersion", "unsupported_version", "must be 1"))
    }
    if document.containsSecrets {
      issues.append(issue("containsSecrets", "unsafe_value", "must be false"))
    }
    if document.containsReplayableCapture {
      issues.append(issue("containsReplayableCapture", "unsafe_value", "must be false"))
    }
    if document.events.isEmpty {
      issues.append(issue("events", "missing_value", "must contain at least one event"))
    }
    if document.events.count > maximumEvents {
      issues.append(issue("events", "size_limit", "contains too many events"))
    }

    var lastRelativeMilliseconds = 0
    var lastStates: [ProtocolCorrelationDocument.StateDomain: ProtocolCorrelationDocument.State] =
      [:]
    let expectedEvidenceClass = evidenceClass(for: document.source)
    for (index, event) in document.events.prefix(maximumEvents).enumerated() {
      let path = "events[\(index)]"
      if event.sequence != index + 1 {
        issues.append(issue("\(path).sequence", "invalid_order", "must be contiguous from 1"))
      }
      if let relative = event.relativeMilliseconds {
        if relative < lastRelativeMilliseconds || relative > 86_400_000 {
          issues.append(
            issue(
              "\(path).relativeMilliseconds",
              "invalid_order",
              "must be monotonic and within one day"
            ))
        }
        lastRelativeMilliseconds = max(lastRelativeMilliseconds, relative)
      }
      validateEvidenceClasses(
        event,
        expected: expectedEvidenceClass,
        at: path,
        issues: &issues
      )
      ProtocolCorrelationContextValidator.validate(event, at: path, issues: &issues)
      ProtocolCorrelationFieldProfileValidator.validate(event, at: path, issues: &issues)
      validateFields(event.fields, at: "\(path).fields", issues: &issues)
      validateTransitions(
        event.transitions,
        at: "\(path).transitions",
        lastStates: &lastStates,
        issues: &issues
      )
    }
    return ProtocolCorrelationValidationReport(issues: issues)
  }

  private static func validateEvidenceClasses(
    _ event: ProtocolCorrelationDocument.Event,
    expected: ProtocolCorrelationDocument.EvidenceClass,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if event.evidenceClass != expected {
      issues.append(issue("\(path).evidenceClass", "source_mismatch", "must match root source"))
    }
    for (index, field) in event.fields.enumerated() where field.evidenceClass != expected {
      issues.append(
        issue("\(path).fields[\(index)].evidenceClass", "source_mismatch", "must match root source")
      )
    }
    for (index, transition) in event.transitions.enumerated()
    where transition.evidenceClass != expected {
      issues.append(
        issue(
          "\(path).transitions[\(index)].evidenceClass",
          "source_mismatch",
          "must match root source"
        ))
    }
    if expected == .synthetic {
      if event.confidence != .unknown {
        issues.append(
          issue("\(path).confidence", "confidence_mismatch", "synthetic must be unknown"))
      }
      for (index, field) in event.fields.enumerated() where field.confidence != .unknown {
        issues.append(
          issue(
            "\(path).fields[\(index)].confidence", "confidence_mismatch",
            "synthetic must be unknown")
        )
      }
      for (index, transition) in event.transitions.enumerated()
      where transition.confidence != .unknown {
        issues.append(
          issue(
            "\(path).transitions[\(index)].confidence",
            "confidence_mismatch",
            "synthetic must be unknown"
          ))
      }
    }
  }

  private static func evidenceClass(for source: ProtocolCorrelationDocument.Source)
    -> ProtocolCorrelationDocument.EvidenceClass
  {
    switch source {
    case .synthetic: return .synthetic
    case .staticBinary: return .staticBinary
    case .runtimeMetadata: return .runtimeMetadata
    case .differentialObservation: return .differentialObservation
    }
  }

  private static func validateFields(
    _ fields: [ProtocolCorrelationDocument.Field],
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if fields.count > maximumFieldsPerEvent {
      issues.append(issue(path, "size_limit", "contains too many fields"))
    }
    var names = Set<String>()
    for (index, field) in fields.prefix(maximumFieldsPerEvent).enumerated() {
      let fieldPath = "\(path)[\(index)]"
      if field.order != index + 1 {
        issues.append(issue("\(fieldPath).order", "invalid_order", "must be contiguous from 1"))
      }
      if !isSafeFieldName(field.name) || !names.insert(field.name).inserted {
        issues.append(
          issue("\(fieldPath).name", "unsafe_value", "must be a unique field-name path")
        )
      }
      validateLength(field, at: fieldPath, issues: &issues)
    }
  }

  private static func validateLength(
    _ field: ProtocolCorrelationDocument.Field,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if (field.length == nil) != (field.lengthUnit == nil) {
      issues.append(issue(path, "invalid_combination", "length and unit must appear together"))
      return
    }
    if let length = field.length, !(0...maximumObservedLength).contains(length) {
      issues.append(issue("\(path).length", "invalid_value", "length is out of bounds"))
    }
    let validUnit: ProtocolCorrelationDocument.LengthUnit?
    switch field.type {
    case .string, .data: validUnit = .bytes
    case .array: validUnit = .elements
    case .dictionary: validUnit = .fields
    case .number, .boolean, .null, .unknown: validUnit = nil
    }
    if field.lengthUnit != validUnit, field.lengthUnit != nil {
      issues.append(issue("\(path).lengthUnit", "invalid_combination", "unit does not match type"))
    }
  }

  private static func validateTransitions(
    _ transitions: [ProtocolCorrelationDocument.StateTransition],
    at path: String,
    lastStates: inout [ProtocolCorrelationDocument.StateDomain: ProtocolCorrelationDocument.State],
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if transitions.count > maximumTransitionsPerEvent {
      issues.append(issue(path, "size_limit", "contains too many transitions"))
    }
    var domains = Set<ProtocolCorrelationDocument.StateDomain>()
    for (index, transition) in transitions.prefix(maximumTransitionsPerEvent).enumerated() {
      let transitionPath = "\(path)[\(index)]"
      if !domains.insert(transition.domain).inserted {
        issues.append(issue("\(transitionPath).domain", "duplicate_value", "must be unique"))
      }
      if !state(transition.from, belongsTo: transition.domain)
        || !state(transition.to, belongsTo: transition.domain)
      {
        issues.append(issue(transitionPath, "invalid_combination", "state does not match domain"))
      }
      if let previous = lastStates[transition.domain], previous != .unknown,
        transition.from != .unknown, previous != transition.from
      {
        issues.append(issue(transitionPath, "state_discontinuity", "from does not match prior to"))
      }
      lastStates[transition.domain] = transition.to
    }
  }

  private static func state(
    _ state: ProtocolCorrelationDocument.State,
    belongsTo domain: ProtocolCorrelationDocument.StateDomain
  ) -> Bool {
    switch domain {
    case .authSession:
      return [.unknown, .signedOut, .authenticating, .valid, .reconnecting, .expired, .failed]
        .contains(state)
    case .controlChannel:
      return [.unknown, .disconnected, .connecting, .online, .resuming, .backoff, .failed]
        .contains(state)
    case .resourceCatalog:
      return [
        .unknown, .unavailable, .refreshing, .ready, .activationPending, .active,
        .deactivationPending, .inactive,
      ].contains(state)
    case .helperTunnel:
      return [.unknown, .idle, .connecting, .established, .degraded, .stopped]
        .contains(state)
    }
  }

  private static func isSafeFieldName(_ value: String) -> Bool {
    value.count <= 128
      && ProtocolCorrelationFieldNamePolicy.allows(value)
      && value.range(
        of: #"^[A-Za-z_][A-Za-z0-9_.\[\]-]*$"#,
        options: .regularExpression
      ) != nil
  }

  private static func issue(_ path: String, _ code: String, _ message: String)
    -> ProtocolCorrelationValidationIssue
  {
    ProtocolCorrelationValidationIssue(path: path, code: code, message: message)
  }
}
