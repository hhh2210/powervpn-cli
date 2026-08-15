import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct ProxyCommandParserTests {
  @Test func sshGrammarPreservesExactNameAndParsesCanonicalIPv4() throws {
    let invocation = try parseProxySSHInvocation(proxySSHArguments)
    #expect(invocation.request.resourceDisplayName == "Marker Resource")
    #expect(invocation.request.sshTarget == .thu21)
    #expect(invocation.destinationText == "11.11.30.21")
    #expect(invocation.destinationIPv4 == 0x0b0b_1e15)
    #expect(invocation.destinationPort == 22)
    #expect(invocation.nonInteractive)

    let interactive = try parseProxySSHInvocation(Array(proxySSHArguments.dropLast()))
    #expect(!interactive.nonInteractive)
  }

  @Test(arguments: [
    "host", "1.2.3", "1.2.3.4.5", "1..2.3", "01.2.3.4", "256.2.3.4",
    "1.2.3.-1", "1.2.3.4/32", "::1", "1.2.3.4\n",
  ])
  func sshRejectsNonCanonicalOrUnsafeDestinations(_ destination: String) {
    var arguments = proxySSHArguments
    arguments[6] = destination
    #expect(throws: ProxyCommandError.self) {
      try parseProxySSHInvocation(arguments)
    }
  }

  @Test(arguments: ["", "0", "65536", "+22", "22x", "-1"])
  func sshRejectsInvalidPorts(_ port: String) {
    var arguments = proxySSHArguments
    arguments[7] = port
    #expect(throws: ProxyCommandError.self) {
      try parseProxySSHInvocation(arguments)
    }
  }

  @Test func sshRejectsOpenGrammarAndUnsafeNamesBeforeRuntime() {
    let invalidShapes = [
      Array(proxySSHArguments.dropLast(2)),
      proxySSHArguments + ["extra"],
      proxySSHArguments.enumerated().map { $0.offset == 1 ? "serve" : $0.element },
      proxySSHArguments.enumerated().map { $0.offset == 5 ? "other" : $0.element },
      proxySSHArguments.enumerated().map { $0.offset == 3 ? "bad\nname" : $0.element },
    ]
    for arguments in invalidShapes {
      #expect(throws: ProxyCommandError.self) {
        try parseProxySSHInvocation(arguments)
      }
    }
  }

  @Test func serveGrammarUsesDefaultAndStrictOptionalOrder() throws {
    let base = Array(proxyServeArguments.prefix(6))
    let invocation = try parseProxyServeInvocation(base)
    #expect(invocation.listenPort == 1080)
    #expect(!invocation.nonInteractive)
    #expect(!invocation.json)

    let complete = try parseProxyServeInvocation(proxyServeArguments)
    #expect(complete.listenPort == 2345)
    #expect(complete.nonInteractive)
    #expect(complete.json)
    #expect(complete.request.sshTarget == .thu52)

    for suffix in [
      ["--json", "--non-interactive"],
      ["--non-interactive", "--listen-port", "2345"],
      ["--listen-port"],
      ["--listen-port", "0"],
      ["--json", "--json"],
      ["--unknown"],
    ] {
      #expect(throws: ProxyCommandError.self) {
        try parseProxyServeInvocation(base + suffix)
      }
    }
  }
}
