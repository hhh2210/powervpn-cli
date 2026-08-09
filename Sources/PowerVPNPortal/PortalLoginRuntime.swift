import Foundation

public enum PortalLoginRuntime {
  /// Runs the sealed R2 portal-only transaction. This API deliberately has no
  /// endpoint, credential, session, tunnel, helper, or insecure-mode inputs.
  public static func runCurrentMachine() async -> PortalLoginReport {
    await PortalLoginRuntimeRunner(dependencies: .currentMachine).run()
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
      let delegate = try PortalURLSessionDelegate.currentMachine()
      return try URLSessionPortalTransport(
        allowedOrigin: origin,
        delegate: delegate
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
    let factory: PortalRequestFactory
    let transport: any PortalTransporting
    let serial: SecureBytes
    do {
      let profile = try dependencies.discoverProfile()
      factory = try PortalRequestFactory(
        profile: profile,
        operatingSystemVersion: dependencies.operatingSystemVersion()
      )
      transport = try dependencies.makeTransport(profile)
      serial = try dependencies.serialReader.read()
    } catch {
      return closedReport(status: .configurationRejected)
    }

    if Task.isCancelled {
      serial.erase()
      factory.eraseSession()
      return closedReport(status: .cancelled)
    }

    let credentials: PortalCredentials
    do {
      credentials = try dependencies.credentialReader.readCredentials()
    } catch SecureTerminalCredentialError.cancelled {
      serial.erase()
      factory.eraseSession()
      return closedReport(status: .cancelled)
    } catch {
      serial.erase()
      factory.eraseSession()
      return closedReport(status: .credentialInputRejected)
    }

    do {
      let workflow = try PortalLoginWorkflow(
        factory: factory,
        transport: transport,
        sleeper: dependencies.sleeper
      )
      return await workflow.run(
        credentials: credentials,
        platformSerial: serial
      )
    } catch {
      credentials.erase()
      serial.erase()
      factory.eraseSession()
      return closedReport(status: .internalFailure)
    }
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
