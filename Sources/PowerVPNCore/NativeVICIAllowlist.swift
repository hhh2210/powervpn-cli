import Foundation

/// The root broker accepts only the wire contract emitted by NativeTrialMaterial.
/// In particular, allowing `load-conn` does not allow certificate files, updown
/// scripts, pools, or future strongSwan options by accident.
public enum NativeVICIAllowlist {
  public static let commands: Set<String> = [
    "version", "load-shared", "unload-shared", "load-conn", "unload-conn", "get-conns",
    "initiate", "terminate", "list-sas", "get-shared",
  ]
  public static let events: Set<String> = ["control-log", "list-sa"]

  public static func validSessionName(_ name: String) -> Bool {
    name.hasPrefix("powervpn-") && (9...128).contains(name.utf8.count)
      && name.utf8.allSatisfy {
        (0x30...0x39).contains($0) || (0x41...0x5A).contains($0)
          || (0x61...0x7A).contains($0) || $0 == 0x2D || $0 == 0x5F
      }
  }

  public static func permits(_ payload: Data) -> Bool {
    guard payload.count <= VICIMessageCodec.maximumPayloadSize,
      let operation = payload.first
    else { return false }
    if operation == VICIPacketOperation.eventRegister.rawValue
      || operation == VICIPacketOperation.eventUnregister.rawValue
    {
      guard payload.count >= 2 else { return false }
      let length = Int(payload[payload.startIndex + 1])
      guard length > 0, payload.count == 2 + length else { return false }
      return events.contains(String(decoding: payload.dropFirst(2), as: UTF8.self))
    }
    guard let request = try? VICINamedRequest.decode(payload: payload),
      commands.contains(request.command)
    else { return false }
    let fields = request.message.elements
    switch request.command {
    case "version", "get-conns", "get-shared": return fields.isEmpty
    case "unload-shared":
      return shape(fields, keys: ["id"]) && session(fields, "id")
    case "unload-conn":
      return shape(fields, keys: ["name"]) && session(fields, "name")
    case "list-sas":
      return fields.isEmpty || (shape(fields, keys: ["ike"]) && session(fields, "ike"))
    case "initiate", "terminate":
      let allowed: Set<String> =
        request.command == "initiate"
        ? ["ike", "child", "timeout", "loglevel"] : ["ike", "force", "timeout", "loglevel"]
      guard
        fields.allSatisfy({
          if case .keyValue(let key, _) = $0 { return allowed.contains(key) }
          return false
        }),
        session(fields, "ike"), value(fields, "loglevel") == "-1",
        let timeout = value(fields, "timeout").flatMap(Int.init), (1...20_000).contains(timeout)
      else { return false }
      if request.command == "initiate" {
        return value(fields, "child").map { $0 == NativeTrialMaterial.childName } ?? true
      }
      return value(fields, "force") == "yes"
    case "load-shared":
      return shape(fields, keys: ["id", "type", "data"], lists: ["owners"])
        && session(fields, "id") && value(fields, "type") == "IKE"
        && bytes(fields, "data").map { !$0.isEmpty } == true
        && list(fields, "owners").map { $0.count == 1 && !$0[0].isEmpty } == true
    case "load-conn":
      guard fields.count == 1, case .section(let name, let connection) = fields[0],
        validSessionName(name)
      else { return false }
      return permitsConnection(connection)
    default: return false
    }
  }

  private static func permitsConnection(_ fields: [VICIElement]) -> Bool {
    guard
      shape(
        fields,
        keys: [
          "version", "aggressive", "local_port", "remote_port", "encap", "keyingtries",
          "reauth_time", "rekey_time", "rand_time", "over_time",
        ],
        lists: ["remote_addrs", "proposals"], sections: ["local", "remote", "children"]),
      value(fields, "version") == "1", value(fields, "aggressive") == "no",
      value(fields, "local_port") == "50020", value(fields, "encap") == "yes",
      value(fields, "keyingtries") == "1", value(fields, "reauth_time") == "0",
      value(fields, "rand_time") == "0", value(fields, "over_time") == "0",
      let port = value(fields, "remote_port").flatMap(Int.init), (1...65535).contains(port),
      let lifetime = value(fields, "rekey_time").flatMap(UInt32.init), lifetime > 0,
      let addresses = list(fields, "remote_addrs"), addresses.count == 1,
      let address = parseStrictIPv4(String(decoding: addresses[0], as: UTF8.self)),
      nativeRoutableHost(address),
      permitsAuth(section(fields, "local")), permitsAuth(section(fields, "remote")),
      let children = section(fields, "children"), children.count == 1,
      case .section(let childName, let child) = children[0],
      childName == NativeTrialMaterial.childName
    else { return false }
    return shape(
      child,
      keys: [
        "start_action", "close_action", "dpd_action", "rekey_time", "rand_time", "life_time",
        "leadsec_addrule", "leadsec_proposal_number",
      ],
      lists: ["local_ts", "remote_ts", "esp_proposals"])
      && ["start_action", "close_action", "dpd_action"].allSatisfy { value(child, $0) == "none" }
      && value(child, "rand_time") == "0"
      && ["0", "1"].contains(value(child, "leadsec_proposal_number") ?? "")
      && list(child, "remote_ts") == [Data("0.0.0.0/0".utf8)]
  }

  private static func permitsAuth(_ fields: [VICIElement]?) -> Bool {
    guard let fields else { return false }
    return shape(fields, keys: ["auth", "id"]) && value(fields, "auth") == "psk"
  }

  private static func shape(
    _ fields: [VICIElement], keys: Set<String> = [], lists: Set<String> = [],
    sections: Set<String> = []
  ) -> Bool {
    fields.count == keys.count + lists.count + sections.count
      && fields.allSatisfy {
        switch $0 {
        case .keyValue(let name, _): keys.contains(name)
        case .list(let name, _): lists.contains(name)
        case .section(let name, _): sections.contains(name)
        }
      }
  }

  private static func bytes(_ fields: [VICIElement], _ key: String) -> Data? {
    for case .keyValue(key, let value) in fields { return value }
    return nil
  }

  private static func value(_ fields: [VICIElement], _ key: String) -> String? {
    bytes(fields, key).flatMap { String(data: $0, encoding: .utf8) }
  }

  private static func session(_ fields: [VICIElement], _ key: String) -> Bool {
    value(fields, key).map(validSessionName) == true
  }

  private static func list(_ fields: [VICIElement], _ key: String) -> [Data]? {
    for case .list(key, let values) in fields { return values }
    return nil
  }

  private static func section(_ fields: [VICIElement], _ key: String) -> [VICIElement]? {
    for case .section(key, let elements) in fields { return elements }
    return nil
  }
}
