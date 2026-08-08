import Foundation

enum ProtocolCorrelationContextValidator {
  static func validate(
    _ event: ProtocolCorrelationDocument.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    switch event.boundary {
    case .controlPlane:
      if event.helperFamily != nil {
        issues.append(issue("\(path).helperFamily", "invalid_combination", "not valid here"))
      }
      guard [.https, .webSocket].contains(event.transport),
        [.clientToServer, .serverToClient].contains(event.direction)
      else {
        issues.append(issue(path, "invalid_combination", "invalid control-plane context"))
        return
      }
      if event.resultClass != nil {
        issues.append(
          issue("\(path).resultClass", "invalid_combination", "not valid on control plane")
        )
      }
      if event.transport == .https {
        validateHTTPS(event, at: path, issues: &issues)
      } else {
        validateWebSocket(event, at: path, issues: &issues)
      }
    case .xpc:
      validateXPC(event, at: path, issues: &issues)
    }
  }

  private static func validateHTTPS(
    _ event: ProtocolCorrelationDocument.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    let operations: Set<ProtocolCorrelationDocument.Operation> = [
      .unknown, .login, .logout, .sessionCheck, .resourceList, .resourceActivate,
      .resourceDeactivate,
    ]
    guard [.request, .response].contains(event.kind), operations.contains(event.operation),
      event.method != nil, let pathTemplate = event.pathTemplate,
      isSafePathTemplate(pathTemplate)
    else {
      issues.append(issue(path, "invalid_combination", "invalid HTTPS metadata"))
      return
    }
    validateKnownHTTPSOperation(event, pathTemplate: pathTemplate, at: path, issues: &issues)
    if event.kind == .request {
      if event.direction != .clientToServer || event.statusCode != nil {
        issues.append(issue(path, "invalid_combination", "invalid HTTPS request direction"))
      }
    } else {
      if event.direction != .serverToClient
        || !(event.statusCode.map { (100...599).contains($0) } ?? true)
      {
        issues.append(issue(path, "invalid_combination", "invalid HTTPS response metadata"))
      }
      if event.evidenceClass == .runtimeMetadata, event.statusCode == nil {
        issues.append(
          issue("\(path).statusCode", "missing_runtime_metadata", "runtime response needs status")
        )
      }
    }
  }

  private static func validateKnownHTTPSOperation(
    _ event: ProtocolCorrelationDocument.Event,
    pathTemplate: String,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    let valid: Bool
    switch event.operation {
    case .login:
      valid =
        event.method == .post
        && [
          "/vpn/user/auth/password",
          "/vpn/user/auth/token",
          "/vpn/user/auth/anonymity",
        ].contains(pathTemplate)
    case .logout:
      valid = event.method == .post && pathTemplate == "/vpn/user/logout"
    case .sessionCheck:
      valid = event.method == .get && pathTemplate == "/vpn/user/check/session"
    case .resourceList:
      valid =
        event.method == .get
        && pathTemplate == "/vpn/user/portal/intergration.xml"
    default:
      return
    }
    if !valid {
      issues.append(
        issue(path, "operation_mismatch", "method and path do not match the known operation")
      )
    }
  }

  private static func validateWebSocket(
    _ event: ProtocolCorrelationDocument.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    guard [.open, .message, .keepalive, .resume, .close].contains(event.kind),
      event.method == nil, event.statusCode == nil
    else {
      issues.append(issue(path, "invalid_combination", "invalid WebSocket metadata"))
      return
    }
    let allowedOperations: Set<ProtocolCorrelationDocument.Operation>
    switch event.kind {
    case .open: allowedOperations = [.unknown, .webSocketOpen]
    case .message:
      allowedOperations = [
        .unknown, .webSocketMessage, .resourceList, .resourceActivate,
        .resourceDeactivate,
      ]
    case .keepalive: allowedOperations = [.unknown, .webSocketKeepalive]
    case .resume: allowedOperations = [.unknown, .webSocketResume]
    case .close: allowedOperations = [.unknown, .webSocketClose]
    default: return
    }
    if !allowedOperations.contains(event.operation) {
      issues.append(issue("\(path).operation", "invalid_combination", "does not match kind"))
    }
    if event.kind == .open {
      if event.direction != .clientToServer
        || !(event.pathTemplate.map(isSafePathTemplate) ?? false)
      {
        issues.append(issue(path, "invalid_combination", "invalid WebSocket open metadata"))
      }
    } else if event.pathTemplate != nil {
      issues.append(issue("\(path).pathTemplate", "invalid_combination", "only open has a path"))
    }
    if event.kind == .resume, event.direction != .clientToServer {
      issues.append(issue(path, "invalid_combination", "resume must be client initiated"))
    }
  }

  private static func validateXPC(
    _ event: ProtocolCorrelationDocument.Event,
    at path: String,
    issues: inout [ProtocolCorrelationValidationIssue]
  ) {
    let operations: Set<ProtocolCorrelationDocument.Operation> = [
      .unknown, .startConnection, .stopConnection, .restartConnection,
      .startAllConnections, .resourceToggleNC, .resourceToggleIPSec, .queryTunnelName,
      .getVersion, .disconnectNotification,
    ]
    guard event.transport == .xpc, event.method == nil, event.pathTemplate == nil,
      event.statusCode == nil, operations.contains(event.operation)
    else {
      issues.append(issue(path, "invalid_combination", "invalid XPC metadata"))
      return
    }
    switch event.kind {
    case .call where event.direction == .guiToHelper && event.resultClass == nil:
      if event.operation == .disconnectNotification {
        issues.append(issue("\(path).operation", "invalid_combination", "not a call operation"))
      }
    case .reply
    where event.direction == .helperToGUI
      && [.success, .failure, .unknown].contains(event.resultClass):
      if event.operation == .disconnectNotification {
        issues.append(issue("\(path).operation", "invalid_combination", "not a reply operation"))
      }
    case .disconnect
    where event.direction == .helperEvent
      && event.resultClass == .disconnect && event.operation == .disconnectNotification:
      break
    default:
      issues.append(issue(path, "invalid_combination", "invalid XPC direction or result"))
    }
  }

  private static func isSafePathTemplate(_ value: String) -> Bool {
    let known: Set<String> = [
      "/vpn/user/auth/password", "/vpn/user/auth/token", "/vpn/user/auth/anonymity",
      "/vpn/user/portal/intergration.xml", "/vpn/user/check/session", "/vpn/user/logout",
    ]
    return known.contains(value) || matches(#"^/<[A-Z][A-Z0-9_]{0,31}>$"#, value)
  }

  private static func matches(_ pattern: String, _ value: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
  }

  private static func issue(_ path: String, _ code: String, _ message: String)
    -> ProtocolCorrelationValidationIssue
  {
    ProtocolCorrelationValidationIssue(path: path, code: code, message: message)
  }
}
