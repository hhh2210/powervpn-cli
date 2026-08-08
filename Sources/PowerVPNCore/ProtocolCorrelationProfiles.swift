import Foundation

enum ProtocolCorrelationFieldProfileValidator {
  private typealias Document = ProtocolCorrelationDocument
  private typealias Field = Document.Field
  private typealias FieldType = Document.FieldType

  private struct Rule {
    let name: String
    let types: [FieldType]

    init(_ name: String, _ types: FieldType...) {
      self.name = name
      self.types = types
    }
  }

  static func validate(
    _ event: ProtocolCorrelationDocument.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if event.operation == .unknown {
      if event.fields.contains(where: { !$0.name.contains("unknownField") }) {
        appendIssue(path, "unknown operation may use placeholder fields only", &issues)
      }
      return
    }
    if event.boundary == .controlPlane, event.transport == .https, event.kind == .request {
      validateHTTPRequest(event, at: path, issues: &issues)
    }
    if event.boundary == .xpc {
      validateXPC(event, at: path, issues: &issues)
    }
  }

  private static func validateHTTPRequest(
    _ event: Document.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    let rules: [Rule]?
    switch event.pathTemplate {
    case "/vpn/user/auth/password":
      rules = ["type", "mac", "verifycode", "username", "password"].map {
        Rule($0, .string, .unknown)
      }
    case "/vpn/user/auth/token": rules = [Rule("token", .string, .data, .unknown)]
    case "/vpn/user/auth/anonymity", "/vpn/user/logout": rules = []
    case "/vpn/user/portal/intergration.xml": rules = [Rule("version", .string)]
    case "/vpn/user/check/session": rules = [Rule("key", .string)]
    default: rules = nil
    }
    if let rules {
      validateExact(event.fields, rules: rules, at: path, issues: &issues)
    }
  }

  private static func validateXPC(
    _ event: Document.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if event.kind == .call {
      switch event.operation {
      case .resourceToggleNC:
        requireFamily(event, .charon, at: path, issues: &issues)
        validateExact(event.fields, rules: toggleRules, at: path, issues: &issues)
      case .resourceToggleIPSec:
        requireFamily(event, .ipsec, at: path, issues: &issues)
        validateExact(event.fields, rules: toggleRules, at: path, issues: &issues)
      case .startConnection:
        validateStart(event, at: path, issues: &issues)
      case .stopConnection:
        requireAnyFamily(event, at: path, issues: &issues)
        validateOptionalTail(
          event.fields,
          required: [Rule("type", .string), Rule("rpc", .string)],
          optional: Rule("tunnel-name", .string),
          at: path,
          issues: &issues
        )
      case .restartConnection:
        requireFamily(event, .ipsec, at: path, issues: &issues)
        validateExact(
          event.fields,
          rules: [Rule("type", .string), Rule("rpc", .string), Rule("common", .dictionary)],
          at: path,
          issues: &issues
        )
      case .queryTunnelName:
        requireFamily(event, .ipsec, at: path, issues: &issues)
        validateOptionalTail(
          event.fields,
          required: [Rule("type", .string), Rule("rpc", .string), Rule("get", .string)],
          optional: Rule("tunnel-name", .string),
          at: path,
          issues: &issues
        )
      case .getVersion:
        requireFamily(event, .charon, at: path, issues: &issues)
        validateExact(
          event.fields,
          rules: [Rule("type", .string), Rule("rpc", .string)],
          at: path,
          issues: &issues
        )
      default: break
      }
    } else if event.kind == .reply {
      validateXPCReply(event, at: path, issues: &issues)
    }
  }

  private static let toggleRules = [
    Rule("type", .string), Rule("rpc", .string), Rule("updown", .boolean),
    Rule("kDeleteActionKey", .string),
  ]

  private static func validateStart(
    _ event: Document.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    requireAnyFamily(event, at: path, issues: &issues)
    let prefix: [Rule]
    let suffix: [Rule]
    switch event.helperFamily {
    case .charon:
      prefix = [
        Rule("type", .string), Rule("rpc", .string), Rule("common", .dictionary),
        Rule("tunnels", .array),
      ]
      suffix = charonStartSuffix
    case .ipsec:
      prefix = [Rule("type", .string), Rule("rpc", .string), Rule("common", .array)]
      suffix = ipsecStartSuffix
    case nil: return
    }
    validatePrefixAndOrderedSubset(
      event.fields,
      prefix: prefix,
      suffix: suffix,
      at: path,
      issues: &issues
    )
  }

  private static let charonStartSuffix = [
    Rule("common.sessionid", .string), Rule("common.vip", .string),
    Rule("common.vipv6", .string), Rule("common.gateway", .string),
    Rule("common.ike_port", .number), Rule("common.majorVersion", .number),
    Rule("common.ike", .string), Rule("common.esp", .string), Rule("common.psk", .string),
    Rule("common.ike_life_time", .number), Rule("common.ipsec_life_time", .number),
    Rule("common.hostItem", .string, .array, .dictionary, .unknown),
    Rule("tunnels[].authority", .number), Rule("tunnels[].status", .number),
    Rule("tunnels[].tunnel-name", .string), Rule("tunnels[].family", .number),
    Rule("tunnels[].rflag", .number), Rule("tunnels[].name", .string),
    Rule("tunnels[].routes", .array), Rule("tunnels[].mapid", .string),
    Rule("tunnels[].negotiate-mode", .number), Rule("tunnels[].routes[].net", .string),
    Rule("tunnels[].routes[].prfix", .number, .string),
  ]

  private static let ipsecStartSuffix = [
    Rule("common.sessionid", .string), Rule("common.vip", .string),
    Rule("common.vipv6", .string), Rule("common.gateway", .string),
    Rule("common.ike_port", .number), Rule("common.natt_port", .number),
    Rule("tunnels[].tunnel-name", .string), Rule("tunnels[].route_addr", .string),
    Rule("tunnels[].ike", .string), Rule("tunnels[].esp", .string),
    Rule("tunnels[].psk", .string),
  ]

  private static func validateXPCReply(
    _ event: Document.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    let rules: [Rule]?
    switch (event.operation, event.helperFamily) {
    case (.resourceToggleNC, .charon): rules = [Rule("updown_nc_success", .boolean)]
    case (.resourceToggleIPSec, .ipsec), (.stopConnection, .charon): rules = []
    case (.stopConnection, .ipsec): rules = [Rule("stop_connection_success", .boolean)]
    case (.queryTunnelName, .ipsec):
      rules = [Rule("name", .string), Rule("get_tun_name_success", .boolean)]
    case (.getVersion, .charon):
      rules = [Rule("version", .string), Rule("get_version", .boolean)]
    default: rules = nil
    }
    if let rules {
      validateExact(event.fields, rules: rules, at: path, issues: &issues)
    }
  }

  private static func requireAnyFamily(
    _ event: Document.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if event.helperFamily == nil {
      appendIssue(path, "helper family is required for this operation", &issues)
    }
  }

  private static func requireFamily(
    _ event: Document.Event,
    _ expected: Document.HelperFamily,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if event.helperFamily != expected {
      appendIssue(path, "helper family does not match the operation", &issues)
    }
  }

  private static func validateExact(
    _ fields: [Field],
    rules: [Rule],
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    guard fields.count == rules.count else {
      appendIssue(path, "field profile count mismatch", &issues)
      return
    }
    for (index, pair) in zip(fields, rules).enumerated() {
      validate(pair.0, against: pair.1, at: "\(path).fields[\(index)]", issues: &issues)
    }
  }

  private static func validateOptionalTail(
    _ fields: [Field],
    required: [Rule],
    optional: Rule,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    guard fields.count == required.count || fields.count == required.count + 1 else {
      appendIssue(path, "field profile count mismatch", &issues)
      return
    }
    validateExact(Array(fields.prefix(required.count)), rules: required, at: path, issues: &issues)
    if fields.count > required.count {
      validate(
        fields[required.count],
        against: optional,
        at: "\(path).fields[\(required.count)]",
        issues: &issues
      )
    }
  }

  private static func validatePrefixAndOrderedSubset(
    _ fields: [Field],
    prefix: [Rule],
    suffix: [Rule],
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    guard fields.count >= prefix.count else {
      appendIssue(path, "required field prefix is missing", &issues)
      return
    }
    validateExact(Array(fields.prefix(prefix.count)), rules: prefix, at: path, issues: &issues)
    var minimumIndex = 0
    for (offset, field) in fields.dropFirst(prefix.count).enumerated() {
      guard let match = suffix[minimumIndex...].firstIndex(where: { $0.name == field.name }) else {
        appendIssue("\(path).fields[\(prefix.count + offset)]", "unexpected field", &issues)
        continue
      }
      validate(
        field,
        against: suffix[match],
        at: "\(path).fields[\(prefix.count + offset)]",
        issues: &issues
      )
      minimumIndex = match + 1
    }
  }

  private static func validate(
    _ field: Field,
    against rule: Rule,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    if field.name != rule.name || !rule.types.contains(field.type) {
      appendIssue(path, "field name, type, or order does not match profile", &issues)
    }
  }

  private static func appendIssue(
    _ path: String,
    _ message: String,
    _ issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    issues.append(
      ProtocolCorrelationValidationIssue(path: path, code: "field_profile", message: message)
    )
  }
}
