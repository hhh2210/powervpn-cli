import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalLoginRuntimeTests {
  @Test func productionOrderIsConfigBeforeTTYAndReportIsValueFree() async throws {
    let trace = RuntimeTrace()
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: acceptedSessionXML),
      .response(status: 200, body: ""),
    ])
    let sleeper = SyntheticPortalSleeper()
    let runner = PortalLoginRuntimeRunner(
      dependencies: runtimeDependencies(
        trace: trace,
        transport: transport,
        sleeper: sleeper,
        credentialOutcome: .success
      )
    )

    let report = await runner.run()

    #expect(report.status == .accepted)
    #expect(report.transactionAccepted)
    #expect(
      trace.snapshot == [
        "discover_profile", "operating_system", "make_transport", "read_serial",
        "read_credentials",
      ]
    )
    #expect(await sleeper.sleeps() == [60])
    let encoded = try JSONEncoder().encode(report)
    let json = String(decoding: encoded, as: UTF8.self)
    for forbidden in [
      "166.111", "runtime-id-sentinel", "runtime-secret-sentinel", "SERIAL",
      "VSG_SESSIONID", "synthetic",
    ] {
      #expect(!json.contains(forbidden))
    }
    #expect(report.safety.credentialSource == "controlling_tty_no_echo")
    #expect(report.safety.endpointSource == "sealed_installed_configuration")
    #expect(!report.safety.credentialInArguments)
    #expect(!report.safety.credentialInEnvironment)
    #expect(!report.safety.credentialWrittenToFile)
    #expect(!report.safety.helperMutationRequested)
    #expect(!report.safety.xpcUsed)
    #expect(!report.safety.viciUsed)
    #expect(!report.safety.ikeTrafficRequested)
  }

  @Test func discoveryFailureNeverReadsSerialCredentialsOrCreatesTransport() async {
    let trace = RuntimeTrace()
    let dependencies = PortalLoginRuntimeDependencies(
      discoverProfile: {
        trace.append("discover_profile")
        throw InstalledConfigDiscoveryError.hashMismatch
      },
      makeTransport: { _ in
        trace.append("make_transport")
        return SyntheticPortalTransport([])
      },
      credentialReader: RuntimeCredentialReader(trace: trace, outcome: .success),
      serialReader: RuntimeSerialReader(trace: trace),
      sleeper: SyntheticPortalSleeper(),
      operatingSystemVersion: {
        trace.append("operating_system")
        return "synthetic-os"
      }
    )
    let report = await PortalLoginRuntimeRunner(dependencies: dependencies).run()
    #expect(report.status == .configurationRejected)
    #expect(trace.snapshot == ["discover_profile"])
    #expect(!report.operations.loginRequested)
  }

  @Test func ttyCancellationErasesPreflightSerialAndSendsNoRequest() async {
    let trace = RuntimeTrace()
    let serialErase = SyntheticEraseObserver()
    let transport = SyntheticPortalTransport([])
    let dependencies = runtimeDependencies(
      trace: trace,
      transport: transport,
      sleeper: SyntheticPortalSleeper(),
      credentialOutcome: .cancelled,
      serialErase: serialErase
    )
    let report = await PortalLoginRuntimeRunner(dependencies: dependencies).run()
    #expect(report.status == .cancelled)
    #expect(trace.snapshot.last == "read_credentials")
    #expect(serialErase.result.count == 1)
    #expect(serialErase.result.allZero)
    #expect(await transport.snapshots().isEmpty)
    #expect(report.ownedMaterial.credentialsErased)
    #expect(report.ownedMaterial.sessionMaterialErased)
  }

  @Test func transportPreflightFailureOccursBeforeTTY() async {
    let trace = RuntimeTrace()
    let dependencies = PortalLoginRuntimeDependencies(
      discoverProfile: {
        trace.append("discover_profile")
        return syntheticPortalProfile()
      },
      makeTransport: { _ in
        trace.append("make_transport")
        throw PortalTransportError.unavailable
      },
      credentialReader: RuntimeCredentialReader(trace: trace, outcome: .success),
      serialReader: RuntimeSerialReader(trace: trace),
      sleeper: SyntheticPortalSleeper(),
      operatingSystemVersion: {
        trace.append("operating_system")
        return "synthetic-os"
      }
    )
    let report = await PortalLoginRuntimeRunner(dependencies: dependencies).run()
    #expect(report.status == .configurationRejected)
    #expect(
      trace.snapshot == ["discover_profile", "operating_system", "make_transport"]
    )
  }

  private func runtimeDependencies(
    trace: RuntimeTrace,
    transport: SyntheticPortalTransport,
    sleeper: any PortalSleeping,
    credentialOutcome: RuntimeCredentialOutcome,
    serialErase: SyntheticEraseObserver? = nil
  ) -> PortalLoginRuntimeDependencies {
    PortalLoginRuntimeDependencies(
      discoverProfile: {
        trace.append("discover_profile")
        return syntheticPortalProfile()
      },
      makeTransport: { _ in
        trace.append("make_transport")
        return transport
      },
      credentialReader: RuntimeCredentialReader(
        trace: trace,
        outcome: credentialOutcome
      ),
      serialReader: RuntimeSerialReader(trace: trace, eraseObserver: serialErase),
      sleeper: sleeper,
      operatingSystemVersion: {
        trace.append("operating_system")
        return "synthetic-os"
      }
    )
  }
}

enum RuntimeCredentialOutcome: Sendable {
  case success
  case cancelled
}

final class RuntimeTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func append(_ event: String) {
    lock.withLock { events.append(event) }
  }

  var snapshot: [String] { lock.withLock { events } }
}

struct RuntimeCredentialReader: SecureTerminalCredentialReading {
  let trace: RuntimeTrace
  let outcome: RuntimeCredentialOutcome

  func readCredentials() throws -> PortalCredentials {
    trace.append("read_credentials")
    switch outcome {
    case .success:
      return PortalCredentials(
        username: try SecureBytes(copying: Array("runtime-id-sentinel".utf8)),
        password: try SecureBytes(copying: Array("runtime-secret-sentinel".utf8))
      )
    case .cancelled: throw SecureTerminalCredentialError.cancelled
    }
  }
}

struct RuntimeSerialReader: PlatformSerialNumberReading {
  let trace: RuntimeTrace
  let eraseObserver: SyntheticEraseObserver?

  init(trace: RuntimeTrace, eraseObserver: SyntheticEraseObserver? = nil) {
    self.trace = trace
    self.eraseObserver = eraseObserver
  }

  func read() throws -> SecureBytes {
    trace.append("read_serial")
    return try syntheticSerial(observer: eraseObserver)
  }
}
