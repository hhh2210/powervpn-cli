import CryptoKit
import Foundation

public struct TunnelSpecVICIDryRunReport: Codable, Equatable, Sendable {
  public struct Metadata: Codable, Equatable, Sendable {
    public let operation: String
    public let ikeVersion: Int
    public let exchangeMode: String
    public let authentication: String
    public let connectionCount: Int
    public let childCount: Int
    public let credentialStorage: String
    public let credentialIdentifierSerialized: Bool
    public let credentialIdentifierDereferenced: Bool
    public let credentialResolved: Bool
    public let secretRead: Bool
    public let secretSerialized: Bool
    public let transportLengthIncluded: Bool
    public let startAction: String
    public let resourceOperations: [String]
    public let resourceCount: Int
    public let ruleIdentifierPresentCount: Int
    public let resourceRuleWireBinding: String
    public let resourceRuleMetadataSerialized: Bool
  }

  public struct SideEffects: Codable, Equatable, Sendable {
    public let socketConnection: Bool
    public let processLaunch: Bool
    public let credentialRead: Bool
    public let securityAssociationMutation: Bool
    public let routeMutation: Bool
    public let policyMutation: Bool
    public let utunMutation: Bool

    public static let none = SideEffects(
      socketConnection: false,
      processLaunch: false,
      credentialRead: false,
      securityAssociationMutation: false,
      routeMutation: false,
      policyMutation: false,
      utunMutation: false
    )

    public var allFalse: Bool {
      !socketConnection && !processLaunch && !credentialRead
        && !securityAssociationMutation && !routeMutation && !policyMutation && !utunMutation
    }
  }

  public let mode: String
  public let payloadByteCount: Int
  public let payloadSHA256: String
  public let metadata: Metadata
  public let sideEffects: SideEffects
}

public struct TunnelSpecVICIDryRunArtifact: Equatable, Sendable {
  public let request: VICINamedRequest
  public let encodedRequestPayload: Data
  public let report: TunnelSpecVICIDryRunReport
}

public enum TunnelSpecVICIDryRunError: Error, Equatable, CustomStringConvertible, Sendable {
  case invalidSchema
  case documentTooLarge
  case unsafeRedactedSpec
  case unsupportedIKEVersion
  case unsupportedExchangeMode
  case unsupportedAuthentication
  case missingTunnelName
  case missingCredentialReference
  case unsupportedCredentialStorage
  case invalidRemoteSelectorCount

  public var description: String {
    switch self {
    case .invalidSchema:
      return "document does not match the closed TunnelSpec schema"
    case .documentTooLarge:
      return "document exceeds the redacted TunnelSpec size limit"
    case .unsafeRedactedSpec:
      return "TunnelSpec contains a value that is not commit-safe redacted data"
    case .unsupportedIKEVersion:
      return "VICI dry run supports IKEv1 only"
    case .unsupportedExchangeMode:
      return "VICI dry run supports IKEv1 main mode only"
    case .unsupportedAuthentication:
      return "VICI dry run supports PSK machine authentication without extended authentication only"
    case .missingTunnelName:
      return "VICI dry run requires a redacted tunnelName"
    case .missingCredentialReference:
      return "VICI dry run requires a credentialReference"
    case .unsupportedCredentialStorage:
      return "credentialReference storage must be keychain or memory"
    case .invalidRemoteSelectorCount:
      return "each VICI dry-run child requires exactly one redacted remote traffic selector"
    }
  }
}

public enum TunnelSpecVICIDryRun {
  public static func build(contentsOf url: URL) throws -> TunnelSpecVICIDryRunArtifact {
    do {
      return try build(data: TunnelSpecRedactedValidator.readBoundedDocument(contentsOf: url))
    } catch TunnelSpecDocumentReadError.sizeLimit {
      throw TunnelSpecVICIDryRunError.documentTooLarge
    }
  }

  public static func build(data: Data) throws -> TunnelSpecVICIDryRunArtifact {
    guard data.count <= TunnelSpecRedactedValidator.maximumDocumentBytes else {
      throw TunnelSpecVICIDryRunError.documentTooLarge
    }
    let spec: TunnelSpec
    do {
      spec = try StrictTunnelSpecDecoder.decode(data)
    } catch {
      throw TunnelSpecVICIDryRunError.invalidSchema
    }
    return try build(spec)
  }

  public static func build(_ spec: TunnelSpec) throws -> TunnelSpecVICIDryRunArtifact {
    guard spec.resources.allSatisfy({ $0.remoteTrafficSelectors.count == 1 }) else {
      throw TunnelSpecVICIDryRunError.invalidRemoteSelectorCount
    }
    guard TunnelSpecRedactedValidator.validate(spec).valid else {
      throw TunnelSpecVICIDryRunError.unsafeRedactedSpec
    }
    guard spec.ikeVersion == 1 else {
      throw TunnelSpecVICIDryRunError.unsupportedIKEVersion
    }
    guard spec.exchangeMode == .main else {
      throw TunnelSpecVICIDryRunError.unsupportedExchangeMode
    }
    guard spec.authentication.machine.lowercased() == "psk",
      spec.authentication.extended.lowercased() == "unknown"
    else {
      throw TunnelSpecVICIDryRunError.unsupportedAuthentication
    }
    guard let tunnelName = spec.tunnelName else {
      throw TunnelSpecVICIDryRunError.missingTunnelName
    }
    guard let credentialReference = spec.credentialReference else {
      throw TunnelSpecVICIDryRunError.missingCredentialReference
    }

    let credentialStorage: String
    switch credentialReference.storage {
    case .keychain:
      credentialStorage = "keychain"
    case .memory:
      credentialStorage = "memory"
    case .opaque, .unknown:
      throw TunnelSpecVICIDryRunError.unsupportedCredentialStorage
    }

    let children = spec.resources.map { resource in
      VICIElement.section(
        name: resource.name,
        elements: [
          .list("local_ts", ["dynamic"]),
          .list("remote_ts", resource.remoteTrafficSelectors),
          .list("esp_proposals", spec.espProposal),
          .keyValue("start_action", "none"),
        ]
      )
    }
    let connection = VICIElement.section(
      name: tunnelName,
      elements: [
        .keyValue("version", "1"),
        .keyValue("aggressive", "no"),
        .list("remote_addrs", [spec.gateway]),
        .list("proposals", spec.ikeProposal),
        .section(
          name: "local",
          elements: [
            .keyValue("auth", "psk"),
            .keyValue("id", spec.localIdentifier),
          ]
        ),
        .section(
          name: "remote",
          elements: [
            .keyValue("auth", "psk"),
            .keyValue("id", spec.remoteIdentifier),
          ]
        ),
        .section(name: "children", elements: children),
      ]
    )
    let request = VICINamedRequest(
      command: "load-conn",
      message: VICIMessage(elements: [connection])
    )
    let payload = try request.encodedPayload()
    let report = TunnelSpecVICIDryRunReport(
      mode: "pure_swift_vici_dry_run",
      payloadByteCount: payload.count,
      payloadSHA256: sha256(payload),
      metadata: .init(
        operation: request.command,
        ikeVersion: 1,
        exchangeMode: "main",
        authentication: "psk",
        connectionCount: 1,
        childCount: children.count,
        credentialStorage: credentialStorage,
        credentialIdentifierSerialized: false,
        credentialIdentifierDereferenced: false,
        credentialResolved: false,
        secretRead: false,
        secretSerialized: false,
        transportLengthIncluded: false,
        startAction: "none",
        resourceOperations: spec.resourceOperations.map(\.rawValue),
        resourceCount: spec.resources.count,
        ruleIdentifierPresentCount: spec.resources.count { $0.ruleIdentifier != nil },
        resourceRuleWireBinding: "unresolved_cp4b",
        resourceRuleMetadataSerialized: false
      ),
      sideEffects: .none
    )
    return TunnelSpecVICIDryRunArtifact(
      request: request,
      encodedRequestPayload: payload,
      report: report
    )
  }

  private static func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
}
