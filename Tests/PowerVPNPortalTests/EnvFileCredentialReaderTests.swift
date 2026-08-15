import Darwin
import Foundation
import Testing

@testable import PowerVPNPortal

/// Writes `content` to a unique temp file with explicit permissions and
/// returns its path.
private func makeCredentialFile(
  _ content: String,
  permissions: mode_t = 0o600
) throws -> String {
  let directory = NSTemporaryDirectory() + "powervpn-envfile-tests-\(UUID().uuidString)"
  try FileManager.default.createDirectory(
    atPath: directory, withIntermediateDirectories: true)
  let path = directory + "/credentials.env"
  let created = FileManager.default.createFile(
    atPath: path, contents: Data(content.utf8))
  precondition(created)
  guard chmod(path, permissions) == 0 else {
    throw IOError("chmod failed: \(String(cString: strerror(errno)))")
  }
  return path
}

private struct IOError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}

private func removeItem(_ path: String) {
  try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent)
}

private func readCredentialFile(_ path: String) throws -> PortalCredentials {
  try EnvFileCredentialReader(path: path).readCredentials()
}

private let envUsernameSentinel = "envfile-user-sentinel"
private let envPasswordSentinel = "envfile-pass-sentinel"

private func validFileContents(
  username: String = envUsernameSentinel,
  password: String = envPasswordSentinel,
  trailingNewline: Bool = true
) -> String {
  "PORTAL_USERNAME=\(username)\nPORTAL_PASSWORD=\(password)" + (trailingNewline ? "\n" : "")
}

@Suite struct EnvFileCredentialReaderTests {
  @Test func parsesStrictFileInBothKeyOrdersWithAndWithoutTrailingNewline() throws {
    for contents in [
      validFileContents(),
      validFileContents(trailingNewline: false),
      "PORTAL_PASSWORD=\(envPasswordSentinel)\nPORTAL_USERNAME=\(envUsernameSentinel)\n",
    ] {
      let path = try makeCredentialFile(contents)
      defer { removeItem(path) }

      let credentials = try readCredentialFile(path)
      #expect(credentials.usernameByteCount == envUsernameSentinel.utf8.count)
      #expect(credentials.passwordByteCount == envPasswordSentinel.utf8.count)
      #expect(
        try credentials.withUsernameBytes {
          String(decoding: $0, as: UTF8.self)
        } == envUsernameSentinel)
      #expect(
        try credentials.withPasswordBytes {
          String(decoding: $0, as: UTF8.self)
        } == envPasswordSentinel)

      credentials.erase()
      #expect(credentials.usernameByteCount == 0)
      #expect(credentials.passwordByteCount == 0)
    }
  }

  @Test func ownerReadOnlyFileIsAccepted() throws {
    let path = try makeCredentialFile(validFileContents(), permissions: 0o400)
    defer { removeItem(path) }
    #expect(try readCredentialFile(path).usernameByteCount == envUsernameSentinel.utf8.count)
  }

  @Test func loosePermissionsFailClosedWithDistinctError() throws {
    for permissions in [mode_t(0o644), 0o640, 0o601, 0o666, 0o777, 0o604] {
      let path = try makeCredentialFile(validFileContents(), permissions: permissions)
      defer { removeItem(path) }

      #expect(throws: EnvFileCredentialError.insecurePermissions) {
        _ = try readCredentialFile(path)
      }
    }
  }

  @Test func symlinkAndDirectoryFailAsNotARegularFile() throws {
    let directory = NSTemporaryDirectory() + "powervpn-envfile-notreg-\(UUID().uuidString)"
    try FileManager.default.createDirectory(
      atPath: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: directory) }

    #expect(throws: EnvFileCredentialError.notARegularFile) {
      _ = try EnvFileCredentialReader(path: directory).readCredentials()
    }

    let target = try makeCredentialFile(validFileContents())
    defer { removeItem(target) }
    let link = (target as NSString).deletingLastPathComponent + "/link.env"
    try? FileManager.default.removeItem(atPath: link)
    guard symlink(target, link) == 0 else {
      throw IOError("symlink failed: \(String(cString: strerror(errno)))")
    }
    #expect(throws: EnvFileCredentialError.notARegularFile) {
      _ = try readCredentialFile(link)
    }
  }

  @Test func missingFileFailsUnreadable() {
    #expect(throws: EnvFileCredentialError.unreadable) {
      _ = try EnvFileCredentialReader(
        path: NSTemporaryDirectory() + "powervpn-envfile-absent-\(UUID().uuidString)"
      ).readCredentials()
    }
  }

  @Test func formatDeviationsFailClosedWithoutLeakingValues() throws {
    let malformedContents = [
      // Duplicate keys.
      "PORTAL_USERNAME=a\nPORTAL_USERNAME=b\nPORTAL_PASSWORD=c\n",
      "PORTAL_PASSWORD=a\nPORTAL_PASSWORD=b\nPORTAL_USERNAME=c\n",
      // Empty values.
      "PORTAL_USERNAME=\nPORTAL_PASSWORD=secret\n",
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD=\n",
      // Missing key.
      "PORTAL_USERNAME=user\n",
      "PORTAL_PASSWORD=secret\n",
      // Extra keys and comments.
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\nEXTRA_KEY=value\n",
      "# comment\nPORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\n",
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\n# trailing comment\n",
      // Carriage returns anywhere.
      "PORTAL_USERNAME=user\r\nPORTAL_PASSWORD=secret\n",
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\r\n",
      "PORTAL_USERNAME=us\rer\nPORTAL_PASSWORD=secret\n",
      // Blank lines and doubled trailing newlines.
      "PORTAL_USERNAME=user\n\nPORTAL_PASSWORD=secret\n",
      "\nPORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\n",
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\n\n",
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD=secret\n\n\n",
      // No separator / separator in wrong place / empty file / newline only.
      "PORTAL_USERNAME user\nPORTAL_PASSWORD=secret\n",
      "=value\nPORTAL_PASSWORD=secret\n",
      "",
      "\n",
      "PORTAL_USERNAME=user\nPORTAL_PASSWORD",
    ]
    for contents in malformedContents {
      let path = try makeCredentialFile(contents)
      defer { removeItem(path) }

      do {
        _ = try readCredentialFile(path)
        Issue.record("expected malformed rejection for: \(contents.debugDescription)")
      } catch let error as EnvFileCredentialError {
        #expect(error == .malformed)
        // Errors must stay value-free: no file bytes may leak through them.
        #expect(!String(describing: error).contains("sentinel"))
      }
    }
  }

  @Test func oversizedValuesFailClosed() throws {
    let longValue = String(repeating: "a", count: EnvFileCredentialReader.maximumValueBytes + 1)
    let path = try makeCredentialFile("PORTAL_USERNAME=\(longValue)\nPORTAL_PASSWORD=x\n")
    defer { removeItem(path) }
    #expect(throws: EnvFileCredentialError.tooLarge) {
      _ = try readCredentialFile(path)
    }
  }

  @Test func parseRejectsCarriageReturnAndValueBytesAreBounded() throws {
    // Direct parse-level checks for the strict two-line contract.
    func parseBytes(_ string: String) throws -> (username: Range<Int>, password: Range<Int>) {
      let bytes = Array(string.utf8)
      return try bytes.withUnsafeBufferPointer {
        try EnvFileCredentialReader.parse(
          UnsafeRawBufferPointer($0))
      }
    }

    let parsed = try parseBytes("PORTAL_USERNAME=abc\nPORTAL_PASSWORD=xyz")
    #expect(parsed.username == 16..<19)
    #expect(parsed.password == 36..<39)

    #expect(throws: EnvFileCredentialError.malformed) {
      _ = try parseBytes("PORTAL_USERNAME=abc\r\nPORTAL_PASSWORD=xyz\n")
    }
  }
}

@Suite struct PortalCredentialPrecedenceTests {
  private struct TracedReader: SecureTerminalCredentialReading {
    let label: String
    let trace: RuntimeTrace

    func readCredentials() throws -> PortalCredentials {
      trace.append(label)
      return PortalCredentials(
        username: try SecureBytes(copying: Array("precedence-user".utf8)),
        password: try SecureBytes(copying: Array("precedence-pass".utf8))
      )
    }
  }

  private struct ThrowingReader: SecureTerminalCredentialReading {
    func readCredentials() throws -> PortalCredentials {
      throw EnvFileCredentialError.insecurePermissions
    }
  }

  @Test func presentFileSelectsEnvReaderAndAbsentFileFallsBackToTerminal() throws {
    let trace = RuntimeTrace()
    let reader = PortalCredentialPrecedenceReader(
      credentialFileExists: { true },
      credentialFileReader: TracedReader(label: "env", trace: trace),
      terminalReader: TracedReader(label: "tty", trace: trace))

    _ = try reader.readCredentials()
    #expect(trace.snapshot == ["env"])

    trace.append("reset")
    let fallback = PortalCredentialPrecedenceReader(
      credentialFileExists: { false },
      credentialFileReader: ThrowingReader(),
      terminalReader: TracedReader(label: "tty", trace: trace))

    _ = try fallback.readCredentials()
    #expect(trace.snapshot == ["env", "reset", "tty"])
  }

  @Test func presentButRejectedFileNeverFallsBackToTerminal() throws {
    let trace = RuntimeTrace()
    let reader = PortalCredentialPrecedenceReader(
      credentialFileExists: { true },
      credentialFileReader: ThrowingReader(),
      terminalReader: TracedReader(label: "tty", trace: trace))

    #expect(throws: EnvFileCredentialError.insecurePermissions) {
      _ = try reader.readCredentials()
    }
    #expect(trace.snapshot.isEmpty)
  }

  @Test func currentMachineResolvesOverrideEnvironmentFailClosed() throws {
    let variable = EnvFileCredentialReader.overrideEnvironmentVariable
    #expect(variable == "POWERVPN_PORTAL_CREDENTIALS")
    let overridePath = "/absolute/credentials.env"

    // Default path: file present selects the env reader at the expanded default.
    let defaultTrace = RuntimeTrace()
    let defaultReader = PortalCredentialPrecedenceReader.currentMachine(
      environment: [:],
      fileExists: { path in
        defaultTrace.append("exists:\(path)")
        return path == (EnvFileCredentialReader.defaultPath as NSString).expandingTildeInPath
      },
      envFileReader: { path in
        defaultTrace.append("env-reader:\(path)")
        return TracedReader(label: "env", trace: defaultTrace)
      },
      terminalReader: TracedReader(label: "tty", trace: defaultTrace))
    _ = try defaultReader.readCredentials()
    #expect(
      defaultTrace.snapshot.contains(
        "env-reader:\((EnvFileCredentialReader.defaultPath as NSString).expandingTildeInPath)"))
    #expect(!defaultTrace.snapshot.contains("tty"))

    // Absolute override: the env reader is built for exactly that path.
    let overrideTrace = RuntimeTrace()
    let overrideReader = PortalCredentialPrecedenceReader.currentMachine(
      environment: [variable: overridePath],
      fileExists: { path in
        overrideTrace.append("exists:\(path)")
        return path == overridePath
      },
      envFileReader: { path in
        overrideTrace.append("env-reader:\(path)")
        return TracedReader(label: "env", trace: overrideTrace)
      },
      terminalReader: ThrowingReader())
    _ = try overrideReader.readCredentials()
    #expect(
      overrideTrace.snapshot == ["env-reader:\(overridePath)", "exists:\(overridePath)", "env"])

    // Relative and empty overrides fail closed without any TTY fallback,
    // regardless of whether the (invalid) path exists.
    for invalid in ["relative/credentials.env", ""] {
      let reader = PortalCredentialPrecedenceReader.currentMachine(
        environment: [variable: invalid],
        fileExists: { _ in false },
        envFileReader: { _ in ThrowingReader() },
        terminalReader: ThrowingReader())
      #expect(throws: EnvFileCredentialError.malformed) {
        _ = try reader.readCredentials()
      }
      let invalidOverrideCountsAsPresent =
        EnvFileCredentialReader.currentMachineCredentialFileExists(
          environment: [variable: invalid], fileExists: { _ in false })
      #expect(invalidOverrideCountsAsPresent)
    }
  }

  // MARK: - Runtime seam integration

  private func runtimeDependencies(
    credentialReader: any SecureTerminalCredentialReading
  ) -> PortalLoginRuntimeDependencies {
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .response(status: 200, body: ""),
    ])
    return PortalLoginRuntimeDependencies(
      discoverProfile: { syntheticPortalProfile() },
      makeTransport: { _ in transport },
      credentialReader: credentialReader,
      serialReader: RuntimeSerialReader(trace: RuntimeTrace()),
      sleeper: SyntheticPortalSleeper(),
      operatingSystemVersion: { "synthetic-os" }
    )
  }

  @Test func runtimeAcceptsValidCredentialFileAndLeaksNoSecretBytes() async throws {
    let path = try makeCredentialFile(validFileContents())
    defer { removeItem(path) }

    let runner = PortalLoginRuntimeRunner(
      dependencies: runtimeDependencies(credentialReader: EnvFileCredentialReader(path: path)))
    let report = await runner.run()

    #expect(report.status == .accepted)
    #expect(report.transactionAccepted)
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
    for forbidden in [envUsernameSentinel, envPasswordSentinel] {
      #expect(!json.contains(forbidden))
    }
  }

  @Test func runtimeMapsInsecureCredentialFileToCredentialInputRejected() async throws {
    let path = try makeCredentialFile(validFileContents(), permissions: 0o644)
    defer { removeItem(path) }

    let runner = PortalLoginRuntimeRunner(
      dependencies: runtimeDependencies(credentialReader: EnvFileCredentialReader(path: path)))
    let report = await runner.run()

    #expect(report.status == .credentialInputRejected)
    #expect(!report.transactionAccepted)
    let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
    for forbidden in [envUsernameSentinel, envPasswordSentinel] {
      #expect(!json.contains(forbidden))
    }
  }

  @Test func runtimeMapsMalformedCredentialFileToCredentialInputRejected() async throws {
    let path = try makeCredentialFile("PORTAL_USERNAME=\(envUsernameSentinel)\n")
    defer { removeItem(path) }

    let runner = PortalLoginRuntimeRunner(
      dependencies: runtimeDependencies(credentialReader: EnvFileCredentialReader(path: path)))
    let report = await runner.run()

    #expect(report.status == .credentialInputRejected)
  }

  @Test func absentFileFallsBackToTerminalReaderEndToEnd() async throws {
    let trace = RuntimeTrace()
    let reader = PortalCredentialPrecedenceReader(
      credentialFileExists: { false },
      credentialFileReader: ThrowingReader(),
      terminalReader: RuntimeCredentialReader(trace: trace, outcome: .success))

    let runner = PortalLoginRuntimeRunner(
      dependencies: runtimeDependencies(credentialReader: reader))
    let report = await runner.run()

    #expect(report.status == .accepted)
    #expect(trace.snapshot == ["read_credentials"])
  }
}
