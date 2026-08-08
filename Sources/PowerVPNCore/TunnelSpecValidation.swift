import Foundation

public struct TunnelSpecValidationIssue: Codable, Equatable, Sendable {
  public let path: String
  public let code: String
  public let message: String

  public init(path: String, code: String, message: String) {
    self.path = path
    self.code = code
    self.message = message
  }
}

public struct TunnelSpecValidationReport: Codable, Equatable, Sendable {
  public let mode: String
  public let valid: Bool
  public let issues: [TunnelSpecValidationIssue]

  public init(issues: [TunnelSpecValidationIssue]) {
    mode = "redacted_fixture"
    valid = issues.isEmpty
    self.issues = issues
  }
}

public enum TunnelSpecRedactedValidator {
  public static func validate(data: Data) -> TunnelSpecValidationReport {
    do {
      return validate(try StrictTunnelSpecDecoder.decode(data))
    } catch {
      return TunnelSpecValidationReport(issues: [
        TunnelSpecValidationIssue(
          path: "$",
          code: "invalid_schema",
          message: "document does not match the closed TunnelSpec schema"
        )
      ])
    }
  }

  public static func validate(_ spec: TunnelSpec) -> TunnelSpecValidationReport {
    var issues: [TunnelSpecValidationIssue] = []

    if spec.schemaVersion != 1 {
      issues.append(issue("schemaVersion", "unsupported_version", "must be 1"))
    }
    if ![1, 2].contains(spec.ikeVersion) {
      issues.append(issue("ikeVersion", "unsupported_value", "must be 1 or 2"))
    }

    requirePlaceholder(spec.gateway, at: "gateway", issues: &issues)
    requirePlaceholder(
      spec.authentication.machine,
      at: "authentication.machine",
      issues: &issues
    )
    requirePlaceholder(
      spec.authentication.extended,
      at: "authentication.extended",
      issues: &issues
    )
    requirePlaceholder(spec.localIdentifier, at: "localIdentifier", issues: &issues)
    requirePlaceholder(spec.remoteIdentifier, at: "remoteIdentifier", issues: &issues)
    requireOptionalPlaceholder(spec.tunnelName, at: "tunnelName", issues: &issues)
    requireOptionalPlaceholder(spec.virtualIP, at: "virtualIP", issues: &issues)
    requireOptionalPlaceholder(spec.mapID, at: "mapID", issues: &issues)
    requireReference(spec.sessionBinding, at: "sessionBinding", issues: &issues)
    requireReference(
      spec.credentialReference,
      at: "credentialReference",
      issues: &issues
    )

    requireProposals(spec.ikeProposal, at: "ikeProposal", issues: &issues)
    requireProposals(spec.espProposal, at: "espProposal", issues: &issues)

    for (index, vendorID) in spec.vendorIds.enumerated() {
      requirePlaceholder(vendorID, at: "vendorIds[\(index)]", issues: &issues)
    }
    for (index, route) in spec.routes.enumerated() {
      requirePlaceholder(route.identifier, at: "routes[\(index)].identifier", issues: &issues)
      requirePlaceholder(route.destination, at: "routes[\(index)].destination", issues: &issues)
    }
    if spec.resourceOperations.isEmpty {
      issues.append(
        issue(
          "resourceOperations",
          "missing_value",
          "must describe ADDRULE, DELRULE, or unknown capability"
        ))
    }

    if spec.resources.isEmpty {
      issues.append(issue("resources", "missing_value", "must contain at least one resource"))
    }
    for (index, resource) in spec.resources.enumerated() {
      requirePlaceholder(resource.name, at: "resources[\(index)].name", issues: &issues)
      requireOptionalPlaceholder(
        resource.ruleIdentifier,
        at: "resources[\(index)].ruleIdentifier",
        issues: &issues
      )
      if resource.remoteTrafficSelectors.isEmpty {
        issues.append(
          issue(
            "resources[\(index)].remoteTrafficSelectors",
            "missing_value",
            "must contain at least one redacted selector"
          ))
      }
      for (selectorIndex, selector) in resource.remoteTrafficSelectors.enumerated() {
        requirePlaceholder(
          selector,
          at: "resources[\(index)].remoteTrafficSelectors[\(selectorIndex)]",
          issues: &issues
        )
      }
    }

    return TunnelSpecValidationReport(issues: issues)
  }

  private static func requireReference(
    _ reference: TunnelSpec.ExternalReference?,
    at path: String,
    issues: inout [TunnelSpecValidationIssue]
  ) {
    guard let reference else { return }
    requirePlaceholder(reference.identifier, at: "\(path).identifier", issues: &issues)
  }

  private static func requireOptionalPlaceholder(
    _ value: String?,
    at path: String,
    issues: inout [TunnelSpecValidationIssue]
  ) {
    guard let value else { return }
    requirePlaceholder(value, at: path, issues: &issues)
  }

  private static func requirePlaceholder(
    _ value: String,
    at path: String,
    issues: inout [TunnelSpecValidationIssue]
  ) {
    guard isSafePlaceholder(value) else {
      issues.append(
        issue(path, "unsafe_value", "must be unknown, redacted, or a safe placeholder")
      )
      return
    }
  }

  private static func requireProposals(
    _ proposals: [String],
    at path: String,
    issues: inout [TunnelSpecValidationIssue]
  ) {
    if proposals.isEmpty {
      issues.append(issue(path, "missing_value", "must contain at least one proposal"))
      return
    }
    for (index, proposal) in proposals.enumerated()
    where !isSafePlaceholder(proposal) && !isAlgorithmProposal(proposal) {
      issues.append(
        issue(
          "\(path)[\(index)]",
          "unsafe_value",
          "must be a safe placeholder or an algorithm-only proposal"
        ))
    }
  }

  private static func isSafePlaceholder(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    let normalized = trimmed.lowercased()
    if ["unknown", "redacted", "<unknown>", "<redacted>", "[redacted]"].contains(normalized) {
      return true
    }
    return matches(#"^<[A-Za-z][A-Za-z0-9_.:-]{0,63}>$"#, trimmed)
      || matches(#"^\$\{[A-Z][A-Z0-9_]{0,63}\}$"#, trimmed)
  }

  private static func isAlgorithmProposal(_ value: String) -> Bool {
    let segments = value.lowercased().split(separator: "-", omittingEmptySubsequences: false)
    guard !segments.isEmpty, !segments.contains(where: { $0.isEmpty }) else { return false }
    let allowed = segments.allSatisfy { segment in
      matches(
        #"^(?:aes(?:128|192|256)?(?:gcm(?:8|12|16))?|3des|des|blowfish|camellia(?:128|192|256)?|sm4|sha(?:1|224|256|384|512)|md5|hmac|prf(?:sha1|sha256|sha384|sha512)?|modp[0-9]+|ecp[0-9]+|curve25519|none|null)$"#,
        String(segment)
      )
    }
    return allowed && value.count <= 128
  }

  private static func matches(_ pattern: String, _ value: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
  }

  private static func issue(_ path: String, _ code: String, _ message: String)
    -> TunnelSpecValidationIssue
  {
    TunnelSpecValidationIssue(path: path, code: code, message: message)
  }
}

private enum StrictTunnelSpecDecoder {
  private static let requiredRootKeys: Set<String> = [
    "schemaVersion", "gateway", "ikeVersion", "exchangeMode", "authentication",
    "localIdentifier", "remoteIdentifier", "natTraversal", "ikeProposal", "espProposal",
    "modeConfig", "vendorIds", "routes", "resourceOperations", "resources",
  ]
  private static let optionalRootKeys: Set<String> = [
    "tunnelName", "virtualIP", "sessionBinding", "mapID", "credentialReference",
  ]
  private static let authenticationKeys: Set<String> = ["machine", "extended"]
  private static let referenceKeys: Set<String> = ["storage", "identifier"]
  private static let routeKeys: Set<String> = ["identifier", "destination"]
  private static let requiredResourceKeys: Set<String> = ["name", "remoteTrafficSelectors"]
  private static let optionalResourceKeys: Set<String> = ["ruleIdentifier"]

  static func decode(_ data: Data) throws -> TunnelSpec {
    let object = try JSONSerialization.jsonObject(with: data)
    guard let root = object as? [String: Any],
      hasOnlyAllowedKeys(root, required: requiredRootKeys, optional: optionalRootKeys),
      hasExactObject(root["authentication"], keys: authenticationKeys),
      hasOptionalExactObject(root, key: "sessionBinding", keys: referenceKeys),
      hasOptionalExactObject(root, key: "credentialReference", keys: referenceKeys),
      let routes = root["routes"] as? [[String: Any]],
      routes.allSatisfy({ Set($0.keys) == routeKeys }),
      let resources = root["resources"] as? [[String: Any]],
      resources.allSatisfy({
        hasOnlyAllowedKeys(
          $0,
          required: requiredResourceKeys,
          optional: optionalResourceKeys
        )
      })
    else {
      throw TunnelSpecDecodingError.invalidShape
    }
    return try JSONDecoder().decode(TunnelSpec.self, from: data)
  }

  private static func hasExactObject(_ value: Any?, keys: Set<String>) -> Bool {
    guard let object = value as? [String: Any] else { return false }
    return Set(object.keys) == keys
  }

  private static func hasOptionalExactObject(
    _ root: [String: Any],
    key: String,
    keys: Set<String>
  ) -> Bool {
    guard let value = root[key] else { return true }
    return hasExactObject(value, keys: keys)
  }

  private static func hasOnlyAllowedKeys(
    _ object: [String: Any],
    required: Set<String>,
    optional: Set<String>
  ) -> Bool {
    let keys = Set(object.keys)
    return required.isSubset(of: keys) && keys.isSubset(of: required.union(optional))
  }
}

private enum TunnelSpecDecodingError: Error {
  case invalidShape
}
