import Foundation

enum StrictTunnelSpecDecoder {
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
    guard ClosedJSONShape.hasUniqueObjectKeys(in: data) else {
      throw TunnelSpecDecodingError.invalidShape
    }
    let object = try JSONSerialization.jsonObject(with: data)
    guard let root = object as? [String: Any],
      ClosedJSONShape.hasOnlyAllowedKeys(
        root,
        required: requiredRootKeys,
        optional: optionalRootKeys
      ),
      ClosedJSONShape.hasExactObject(root["authentication"], keys: authenticationKeys),
      ClosedJSONShape.hasOptionalExactObject(root, key: "sessionBinding", keys: referenceKeys),
      ClosedJSONShape.hasOptionalExactObject(
        root,
        key: "credentialReference",
        keys: referenceKeys
      ),
      let routes = root["routes"] as? [[String: Any]],
      routes.allSatisfy({ Set($0.keys) == routeKeys }),
      let resources = root["resources"] as? [[String: Any]],
      resources.allSatisfy({
        ClosedJSONShape.hasOnlyAllowedKeys(
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
}

private enum TunnelSpecDecodingError: Error {
  case invalidShape
}
