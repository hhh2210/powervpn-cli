import Foundation
import PowerVPNPortal

package enum ProductM2FreshSSHCommandError: Error, Equatable, Sendable {
  case invalidChallenge
  case invalidHomeDirectory
  case unresolvedTarget
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

    guard let destination = target.resolvedDestination else {
      throw ProductM2FreshSSHCommandError.unresolvedTarget
    }
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

package struct ProductM2SSHResolvedDestination: Sendable {
  let host: String
  let ipv4: UInt32
  let user: String
}

extension ProductM2SSHTarget {
  package init(
    key: String,
    configuration: PowerVPNTargetsConfiguration
  ) throws {
    let target = try configuration.target(named: key)
    self.init(
      rawValue: key,
      host: target.host,
      ipv4: target.ipv4,
      user: target.user
    )
  }

  fileprivate var resolvedDestination: ProductM2SSHResolvedDestination? {
    guard let host, let ipv4, let user else { return nil }
    return ProductM2SSHResolvedDestination(host: host, ipv4: ipv4, user: user)
  }

  package var resolvedTargetIPv4: UInt32? { ipv4 }

  package var requiredTargetIPv4: UInt32 {
    guard let ipv4 else { preconditionFailure("unresolved SSH target") }
    return ipv4
  }
}
