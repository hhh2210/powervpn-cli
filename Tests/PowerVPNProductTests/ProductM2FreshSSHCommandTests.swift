import Foundation
import PowerVPNPortal
import Testing

@testable import PowerVPNProduct

@Suite struct ProductM2FreshSSHCommandTests {
  private let challenge = "0123456789abcdef0123456789abcdef"

  @Test func configuredTargetsUseResolvedNumericDestinationsAndUsers() throws {
    let configuration = try PowerVPNTargetsConfiguration.decode(
      Data(
        """
        {"portalOrigin":"https://192.0.2.1:4443","targets":{
          "lab-a":{"host":"192.0.2.21","user":"synthetic-user"},
          "lab-third":{"host":"198.51.100.7","user":"third_user"}
        }}
        """.utf8
      ))
    let cases: [(String, String, UInt32, String)] = [
      ("lab-a", "192.0.2.21", 0xC000_0215, "synthetic-user"),
      ("lab-third", "198.51.100.7", 0xC633_6407, "third_user"),
    ]
    for (key, host, address, user) in cases {
      let target = try ProductM2SSHTarget(key: key, configuration: configuration)
      let command = try ProductM2FreshSSHCommand.make(
        target: target,
        challenge: challenge,
        homeDirectory: "/Users/tester"
      )
      #expect(command.targetIPv4 == address)
      #expect(command.arguments.suffix(2).first == host)
      #expect(command.arguments.contains("HostKeyAlias=\(host)"))
      #expect(command.arguments.contains("UserKnownHostsFile=/Users/tester/.ssh/known_hosts"))
      #expect(command.arguments.contains("-l"))
      #expect(command.arguments.contains(user))
      #expect(command.expectedStandardOutput == Data("POWERVPN_M2:\(challenge)\n".utf8))
    }
  }

  @Test func commandForcesFreshStrictNonInteractiveTransport() throws {
    let command = try ProductM2FreshSSHCommand.make(
      target: .thu21,
      challenge: challenge,
      homeDirectory: "/Users/tester"
    )
    #expect(ProductM2FreshSSHCommand.executable == "/usr/bin/ssh")
    #expect(ProductM2FreshSSHCommand.timeout == .seconds(15))
    #expect(
      Array(command.arguments.prefix(6)) == [
        "-F", "/dev/null", "-n", "-T", "-S", "none",
      ])
    let requiredOptions = [
      "BatchMode=yes", "ConnectTimeout=10", "ConnectionAttempts=1",
      "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
      "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "VerifyHostKeyDNS=no",
      "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
      "PreferredAuthentications=publickey", "ForwardAgent=no",
      "ClearAllForwardings=yes", "PermitLocalCommand=no", "RequestTTY=no",
      "ProxyCommand=none", "ProxyJump=none", "CanonicalizeHostname=no",
      "LogLevel=ERROR", "ServerAliveInterval=3", "ServerAliveCountMax=1",
      "AddKeysToAgent=no", "UseKeychain=no",
    ]
    for option in requiredOptions {
      #expect(command.arguments.contains(option))
    }
    #expect(command.arguments.suffix(1).first == "printf 'POWERVPN_M2:%s\\n' '\(challenge)'")
  }

  @Test func onlyStrictLowercase128BitChallengesAreAccepted() throws {
    let rejected = [
      "", "0123456789abcdef", "0123456789ABCDEF0123456789ABCDEF",
      "g123456789abcdef0123456789abcdef",
      "0123456789abcdef0123456789abcdef0",
    ]
    for value in rejected {
      #expect(throws: ProductM2FreshSSHCommandError.invalidChallenge) {
        try ProductM2FreshSSHCommand.make(
          target: .thu21, challenge: value, homeDirectory: "/Users/tester")
      }
    }
  }

  @Test func homeDirectoryMustBeAbsoluteAndSingleLine() throws {
    for path in ["relative", "/Users/tester\n-o Bad=yes", "/Users/tester\0tail"] {
      #expect(throws: ProductM2FreshSSHCommandError.invalidHomeDirectory) {
        try ProductM2FreshSSHCommand.make(
          target: .thu21, challenge: challenge, homeDirectory: path)
      }
    }
  }
}
