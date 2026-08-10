import Foundation

package enum ProductM2FreshSSHCommandError: Error, Equatable, Sendable {
  case invalidChallenge
  case invalidHomeDirectory
}

package struct ProductM2FreshSSHCommand: Equatable, Sendable {
  package static let executable = "/usr/bin/ssh"
  package static let timeout: Duration = .seconds(15)
  package static let timeoutMilliseconds = 15_000
  package static let outputLimitBytes = 512

  package let target: ProductM2SSHTarget
  package let targetIPv4: UInt32
  package let arguments: [String]
  package let expectedStandardOutput: Data

  package static func make(
    target: ProductM2SSHTarget,
    challenge: String,
    homeDirectory: String
  ) throws -> Self {
    guard challenge.utf8.count == 32,
      challenge.utf8.allSatisfy({
        (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
      })
    else { throw ProductM2FreshSSHCommandError.invalidChallenge }
    guard homeDirectory.hasPrefix("/"), !homeDirectory.contains("\n"),
      !homeDirectory.contains("\r"), !homeDirectory.contains("\0")
    else { throw ProductM2FreshSSHCommandError.invalidHomeDirectory }

    let destination = target.lockedDestination
    let knownHosts = URL(fileURLWithPath: homeDirectory, isDirectory: true)
      .appendingPathComponent(".ssh/known_hosts").path
    let options = [
      "BatchMode=yes",
      "ConnectTimeout=10",
      "ConnectionAttempts=1",
      "ControlMaster=no",
      "ControlPath=none",
      "ControlPersist=no",
      "StrictHostKeyChecking=yes",
      "UserKnownHostsFile=\(knownHosts)",
      "UpdateHostKeys=no",
      "VerifyHostKeyDNS=no",
      "PasswordAuthentication=no",
      "KbdInteractiveAuthentication=no",
      "PreferredAuthentications=publickey",
      "ForwardAgent=no",
      "ClearAllForwardings=yes",
      "PermitLocalCommand=no",
      "RequestTTY=no",
      "ProxyCommand=none",
      "ProxyJump=none",
      "CanonicalizeHostname=no",
      "LogLevel=ERROR",
      "ServerAliveInterval=3",
      "ServerAliveCountMax=1",
      "AddKeysToAgent=no",
      "UseKeychain=no",
      "HostKeyAlias=\(destination.host)",
    ]
    var arguments = ["-F", "/dev/null", "-n", "-T", "-S", "none"]
    for option in options {
      arguments.append(contentsOf: ["-o", option])
    }
    arguments.append(contentsOf: [
      "-l", destination.user,
      "-p", "22",
      "--", destination.host,
      "printf 'POWERVPN_M2:%s\\n' '\(challenge)'",
    ])
    return Self(
      target: target,
      targetIPv4: destination.ipv4,
      arguments: arguments,
      expectedStandardOutput: Data("POWERVPN_M2:\(challenge)\n".utf8)
    )
  }
}

private struct ProductM2SSHLockedDestination: Sendable {
  let host: String
  let ipv4: UInt32
  let user: String
}

extension ProductM2SSHTarget {
  fileprivate var lockedDestination: ProductM2SSHLockedDestination {
    switch self {
    case .thu21:
      ProductM2SSHLockedDestination(
        host: "11.11.30.21", ipv4: 0x0B0B_1E15, user: "lijuanzi")
    case .thu52:
      ProductM2SSHLockedDestination(
        host: "11.11.37.52", ipv4: 0x0B0B_2534, user: "lijuanzi")
    }
  }

  package var requiredTargetIPv4: UInt32 { lockedDestination.ipv4 }
}
