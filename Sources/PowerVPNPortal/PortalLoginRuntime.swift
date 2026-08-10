import Foundation

public enum PortalLoginRuntime {
  /// Runs the sealed R2 portal-only transaction. This API deliberately has no
  /// endpoint, credential, session, tunnel, helper, or insecure-mode inputs.
  public static func runCurrentMachine() async -> PortalLoginReport {
    await PortalLoginRuntimeRunner(dependencies: .currentMachine).run()
  }

  /// Acquires a live, memory-only portal lease without starting a helper.
  /// Calling this performs TTY credential input and portal network requests;
  /// the product must obtain explicit user approval immediately beforehand.
  package static func acquireCurrentMachine() async -> PortalSnapshotAcquisitionResult {
    await PortalLoginRuntimeRunner(dependencies: .currentMachine).acquire()
  }
}

struct PortalLoginRuntimeDependencies: Sendable {
  let discoverProfile: @Sendable () throws -> InstalledPortalProfile
  let makeTransport: @Sendable (InstalledPortalProfile) throws -> any PortalTransporting
  let credentialReader: any SecureTerminalCredentialReading
  let serialReader: any PlatformSerialNumberReading
  let sleeper: any PortalSleeping
  let operatingSystemVersion: @Sendable () -> String

  static let currentMachine = PortalLoginRuntimeDependencies(
    discoverProfile: { try InstalledConfigDiscovery.discoverCurrentMachine() },
    makeTransport: { profile in
      guard let host = profile.origin.host else {
        throw PortalTransportError.invalidOrigin
      }
      let origin = try PortalHTTPOrigin(host: host, port: profile.origin.port ?? 443)
      let passwordTransport = try CurlPasswordPortalTransport(allowedOrigin: origin)
      let delegate = try PortalURLSessionDelegate.currentMachine()
      let sessionTransport = try URLSessionPortalTransport(
        allowedOrigin: origin,
        delegate: delegate
      )
      return LeadSecPortalTransport(
        allowedOrigin: origin,
        passwordTransport: passwordTransport,
        sessionTransport: sessionTransport
      )
    },
    credentialReader: DarwinSecureTerminalCredentialReader(),
    serialReader: InstalledPlatformSerialNumberReader(),
    sleeper: ContinuousPortalSleeper(),
    operatingSystemVersion: {
      ProcessInfo.processInfo.operatingSystemVersionString
    }
  )
}

struct PortalLoginRuntimeRunner: Sendable {
  let dependencies: PortalLoginRuntimeDependencies

  func run() async -> PortalLoginReport {
    let prepared: PreparedPortalRuntime
    do {
      prepared = try prepare()
    } catch {
      return closedReport(status: .configurationRejected)
    }

    if Task.isCancelled {
      prepared.erase()
      return closedReport(status: .cancelled)
    }

    let credentials: PortalCredentials
    do {
      credentials = try dependencies.credentialReader.readCredentials()
    } catch SecureTerminalCredentialError.cancelled {
      prepared.erase()
      return closedReport(status: .cancelled)
    } catch {
      prepared.erase()
      return closedReport(status: .credentialInputRejected)
    }

    do {
      let workflow = try PortalLoginWorkflow(
        factory: prepared.factory,
        transport: prepared.transport,
        sleeper: dependencies.sleeper
      )
      return await workflow.run(
        credentials: credentials,
        platformSerial: prepared.serial
      )
    } catch {
      credentials.erase()
      prepared.erase()
      return closedReport(status: .internalFailure)
    }
  }

  func acquire() async -> PortalSnapshotAcquisitionResult {
    let prepared: PreparedPortalRuntime
    do {
      prepared = try prepare()
    } catch {
      return .rejected(closedReport(status: .configurationRejected))
    }
    if Task.isCancelled {
      prepared.erase()
      return .rejected(closedReport(status: .cancelled))
    }

    let credentials: PortalCredentials
    do {
      credentials = try dependencies.credentialReader.readCredentials()
    } catch SecureTerminalCredentialError.cancelled {
      prepared.erase()
      return .rejected(closedReport(status: .cancelled))
    } catch {
      prepared.erase()
      return .rejected(closedReport(status: .credentialInputRejected))
    }

    do {
      let workflow = try PortalLoginWorkflow(
        factory: prepared.factory,
        transport: prepared.transport,
        sleeper: dependencies.sleeper
      )
      return await workflow.acquire(
        credentials: credentials,
        platformSerial: prepared.serial
      )
    } catch {
      credentials.erase()
      prepared.erase()
      return .rejected(closedReport(status: .internalFailure))
    }
  }

  private func prepare() throws -> PreparedPortalRuntime {
    let profile = try dependencies.discoverProfile()
    return PreparedPortalRuntime(
      factory: try PortalRequestFactory(
        profile: profile,
        operatingSystemVersion: dependencies.operatingSystemVersion()
      ),
      transport: try dependencies.makeTransport(profile),
      serial: try dependencies.serialReader.read()
    )
  }

  private func closedReport(status: PortalLoginStatus) -> PortalLoginReport {
    PortalLoginReport(
      status: status,
      operations: PortalOperationEvidence(
        loginRequested: false,
        loginAccepted: false,
        sessionCheckRequested: false,
        sessionCheckAccepted: false,
        resourceListRequested: false,
        resourceListAccepted: false,
        logoutRequested: false,
        logoutAccepted: false
      ),
      ownedMaterial: PortalOwnedMaterialEvidence(
        credentialsErased: true,
        requestBodiesErased: true,
        responseBodiesErased: true,
        sessionMaterialErased: true
      )
    )
  }
}

private struct PreparedPortalRuntime: Sendable {
  let factory: PortalRequestFactory
  let transport: any PortalTransporting
  let serial: SecureBytes

  func erase() {
    serial.erase()
    factory.eraseSession()
    transport.cancel()
  }
}
