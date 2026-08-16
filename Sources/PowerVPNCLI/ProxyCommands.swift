import Foundation
import PowerVPNPortal
import PowerVPNProduct

enum ProxyCommandError: Error, Equatable, CustomStringConvertible {
  case invalidSSHArguments
  case invalidServeArguments

  var description: String {
    switch self {
    case .invalidSSHArguments:
      return "usage: powervpn proxy ssh --resource-display-name <exact> "
        + "--ssh-target <key> <numeric-ipv4> <port> [--non-interactive]"
    case .invalidServeArguments:
      return "usage: powervpn proxy serve --resource-display-name <exact> "
        + "--ssh-target <key> [--listen-port <1-65535>] "
        + "[--non-interactive] [--json]"
    }
  }
}

struct ProxySSHInvocation: Equatable, Sendable {
  let request: ProductM2ConnectRequest
  let destinationText: String
  let destinationIPv4: UInt32
  let destinationPort: UInt16
  let nonInteractive: Bool
}

struct ProxyServeInvocation: Equatable, Sendable {
  let request: ProductM2ConnectRequest
  let listenPort: UInt16
  let nonInteractive: Bool
  let json: Bool
}

func parseProxySSHInvocation(
  _ arguments: [String],
  resolveTarget: (String) throws -> ProductM2SSHTarget = defaultProxySSHTarget
) throws -> ProxySSHInvocation {
  let nonInteractive = arguments.count == 9
  guard arguments.count == 8 || nonInteractive,
    arguments[0] == "proxy",
    arguments[1] == "ssh",
    arguments[2] == "--resource-display-name",
    arguments[4] == "--ssh-target",
    !nonInteractive || arguments[8] == "--non-interactive",
    validResourceDisplayName(arguments[3]),
    let target = try? resolveTarget(arguments[5]),
    let address = parseProxyIPv4(arguments[6]),
    let port = parseProxyPort(arguments[7])
  else { throw ProxyCommandError.invalidSSHArguments }

  return ProxySSHInvocation(
    request: ProductM2ConnectRequest(
      resourceDisplayName: arguments[3],
      sshTarget: target
    ),
    destinationText: arguments[6],
    destinationIPv4: address,
    destinationPort: port,
    nonInteractive: nonInteractive
  )
}

func parseProxyServeInvocation(
  _ arguments: [String],
  resolveTarget: (String) throws -> ProductM2SSHTarget = defaultProxySSHTarget
) throws -> ProxyServeInvocation {
  guard arguments.count >= 6,
    arguments[0] == "proxy",
    arguments[1] == "serve",
    arguments[2] == "--resource-display-name",
    arguments[4] == "--ssh-target",
    validResourceDisplayName(arguments[3]),
    let target = try? resolveTarget(arguments[5])
  else { throw ProxyCommandError.invalidServeArguments }

  var index = 6
  var listenPort: UInt16 = 1080
  var nonInteractive = false
  var json = false
  if index < arguments.count, arguments[index] == "--listen-port" {
    guard index + 1 < arguments.count,
      let parsedPort = parseProxyPort(arguments[index + 1])
    else { throw ProxyCommandError.invalidServeArguments }
    listenPort = parsedPort
    index += 2
  }
  if index < arguments.count, arguments[index] == "--non-interactive" {
    nonInteractive = true
    index += 1
  }
  if index < arguments.count, arguments[index] == "--json" {
    json = true
    index += 1
  }
  guard index == arguments.count else {
    throw ProxyCommandError.invalidServeArguments
  }

  return ProxyServeInvocation(
    request: ProductM2ConnectRequest(
      resourceDisplayName: arguments[3],
      sshTarget: target
    ),
    listenPort: listenPort,
    nonInteractive: nonInteractive,
    json: json
  )
}

func parseProxyIPv4(_ text: String) -> UInt32? {
  let parts = text.split(separator: ".", omittingEmptySubsequences: false)
  guard parts.count == 4 else { return nil }
  var value: UInt32 = 0
  for part in parts {
    guard !part.isEmpty,
      part.count <= 3,
      part.count == 1 || part.first != "0",
      part.utf8.allSatisfy({ (48...57).contains($0) }),
      let octet = UInt32(part),
      octet <= 255
    else { return nil }
    value = (value << 8) | octet
  }
  return value
}

func parseProxyPort(_ text: String) -> UInt16? {
  guard !text.isEmpty,
    text.utf8.allSatisfy({ (48...57).contains($0) }),
    let value = UInt32(text),
    (1...65_535).contains(value)
  else { return nil }
  return UInt16(value)
}

private func defaultProxySSHTarget(_ text: String) throws -> ProductM2SSHTarget {
  guard let target = ProductM2SSHTarget(rawValue: text) else {
    throw ProxyCommandError.invalidSSHArguments
  }
  return target
}
