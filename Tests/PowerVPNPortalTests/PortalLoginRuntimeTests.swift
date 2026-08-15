import CPortalCurl
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
    #expect(report.safety.endpointSource == "operator_approved_fixed_local_mvp")
    #expect(report.safety.trustMode == "operator_approved_tofu")
    #expect(report.safety.fixedSPKIPinRequired)
    #expect(!report.safety.systemTrustRequired)
    #expect(!report.safety.releaseReady)
    #expect(!report.safety.credentialInArguments)
    #expect(!report.safety.credentialInEnvironment)
    #expect(!report.safety.credentialWrittenToFile)
    #expect(!report.safety.helperMutationRequested)
    #expect(!report.safety.xpcUsed)
    #expect(!report.safety.viciUsed)
    #expect(!report.safety.ikeTrafficRequested)
  }

  @Test func acquisitionRuntimeStopsAfterResourceUntilExplicitLogout() async throws {
    let trace = RuntimeTrace()
    let transport = SyntheticPortalTransport([
      .response(status: 200, body: acceptedLoginXML, setCookie: syntheticSessionCookie),
      .response(status: 200, body: acceptedResourceXML),
      .response(status: 200, body: ""),
    ])
    let runner = PortalLoginRuntimeRunner(
      dependencies: runtimeDependencies(
        trace: trace,
        transport: transport,
        sleeper: SyntheticPortalSleeper(),
        credentialOutcome: .success
      )
    )

    let result = await runner.acquire()
    guard case .acquired(let lease) = result else {
      Issue.record("unexpected acquisition rejection")
      return
    }

    #expect(
      trace.snapshot == [
        "discover_profile", "operating_system", "make_transport", "read_serial",
        "read_credentials",
      ]
    )
    #expect(await transport.snapshots().map(\.method) == [.post, .get])
    #expect(
      await lease.logoutAndErase()
        == PortalLeaseLogoutResult(
          status: .accepted,
          failureClass: .completedRemoteExchange
        )
    )
    #expect(await transport.snapshots().map(\.method) == [.post, .get, .post])
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

  @Test func transportPreflightFailureOccursBeforeTTY() async throws {
    let trace = RuntimeTrace()
    let failure = try #require(
      CPortalCurlDriver.normalizedFailure(PVCURL_STATUS_SETUP_FAILED)
    )
    let dependencies = PortalLoginRuntimeDependencies(
      discoverProfile: {
        trace.append("discover_profile")
        return syntheticPortalProfile()
      },
      makeTransport: { _ in
        trace.append("make_transport")
        throw failure
      },
      credentialReader: RuntimeCredentialReader(trace: trace, outcome: .success),
      serialReader: RuntimeSerialReader(trace: trace),
      sleeper: SyntheticPortalSleeper(),
      operatingSystemVersion: {
        trace.append("operating_system")
        return "synthetic-os"
      }
    )
    let result = await PortalLoginRuntimeRunner(dependencies: dependencies).acquire()
    guard case .rejected(let report) = result else {
      Issue.record("unexpected accepted acquisition")
      return
    }
    #expect(report.status == .configurationRejected)
    #expect(report.transportFailure?.category == .setupFailed)
    #expect(report.transportFailure?.setCookieFieldCount == nil)
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
