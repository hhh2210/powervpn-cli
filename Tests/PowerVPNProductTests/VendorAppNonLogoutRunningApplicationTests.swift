import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppNonLogoutRunningApplicationTests {
  @Test func wrongOperatingSystemRejectsBeforeLaunch() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(
        trace: trace,
        systemIdentity: .init(productVersion: "27.0", buildVersion: "wrong")
      ))

    #expect(isNotLaunched(await launcher.launch()))
    #expect(trace.openCount == 0)
    #expect(trace.forceCount == 0)
  }

  @Test func wrongInstalledApplicationRejectsBeforeLaunch() async {
    let trace = VendorAppHandoffBridgeTrace()
    let required = VendorAppHandoffBundleIdentity.required
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(
        trace: trace,
        bundleIdentity: .init(
          bundleIdentifier: required.bundleIdentifier,
          bundlePath: required.bundlePath,
          executablePath: required.executablePath,
          shortVersion: required.shortVersion,
          buildVersion: "wrong",
          executableArchitectures: required.executableArchitectures
        )
      ))

    #expect(isNotLaunched(await launcher.launch()))
    #expect(trace.openCount == 0)
    #expect(trace.forceCount == 0)
  }

  @Test func invalidStaticSignatureRejectsBeforeLaunch() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(trace: trace, staticCodeIsValid: false))

    #expect(isNotLaunched(await launcher.launch()))
    #expect(trace.openCount == 0)
    #expect(trace.forceCount == 0)
  }

  @Test func preexistingBundleInstanceRejectsBeforeLaunch() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(trace: trace, runningApplicationCount: 1))

    #expect(isNotLaunched(await launcher.launch()))
    #expect(trace.openCount == 0)
    #expect(trace.forceCount == 0)
  }

  @Test func callbackWithoutApplicationRemainsNotLaunched() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(trace: trace, openResult: .notLaunched))

    #expect(isNotLaunched(await launcher.launch()))
    #expect(trace.openCount == 1)
    #expect(trace.identityCheckCount == 0)
    #expect(trace.forceCount == 0)
  }

  @Test func callbackApplicationWithoutReceiverSealIsReportedStillRunning() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(
        trace: trace,
        openResult: .launchedButUnusable(stillRunning: { true })
      ))

    guard case .launchedButUnusable(let stillRunning) = await launcher.launch() else {
      Issue.record("launched application without a receiver seal was not preserved")
      return
    }
    #expect(stillRunning())
    #expect(trace.openCount == 1)
    #expect(trace.identityCheckCount == 0)
    #expect(trace.forceCount == 0)
  }

  @Test func candidateWithRejectedIdentityIsReportedStillRunning() async {
    let trace = VendorAppHandoffBridgeTrace(identityIsCurrent: false)
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(trace: trace))

    guard case .launchedButUnusable(let stillRunning) = await launcher.launch() else {
      Issue.record("opened candidate with rejected identity was collapsed into not-launched")
      return
    }
    #expect(stillRunning())
    #expect(trace.openCount == 1)
    #expect(trace.identityCheckCount == 1)
    #expect(trace.forceCount == 0)
  }

  @Test func validCandidateForcesItsExactReceiverOnce() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(trace: trace))
    guard case .ready(let application) = await launcher.launch() else {
      Issue.record("valid exact receiver was not returned ready")
      return
    }

    #expect(application.identityIsCurrent)
    #expect(!application.isTerminated)
    #expect(application.forceTerminate())
    #expect(trace.openCount == 1)
    #expect(trace.forceCount == 1)
  }

  @Test func identityChangeBeforeForceFailsWithoutMutation() async {
    let trace = VendorAppHandoffBridgeTrace()
    let launcher = InstalledVendorAppHandoffLauncher(
      dependencies: testDependencies(trace: trace))
    guard case .ready(let application) = await launcher.launch() else {
      Issue.record("valid exact receiver was not returned ready")
      return
    }

    trace.setIdentityIsCurrent(false)
    #expect(!application.identityIsCurrent)
    #expect(!application.forceTerminate())
    #expect(trace.forceCount == 0)
  }
}

private func testDependencies(
  trace: VendorAppHandoffBridgeTrace,
  systemIdentity: VendorAppHandoffSystemIdentity? = .required,
  bundleIdentity: VendorAppHandoffBundleIdentity? = .required,
  staticCodeIsValid: Bool = true,
  runningApplicationCount: Int = 0,
  openResult: VendorAppHandoffOpenResult? = nil
) -> VendorAppHandoffLaunchDependencies {
  VendorAppHandoffLaunchDependencies(
    systemIdentity: { systemIdentity },
    bundleIdentity: { bundleIdentity },
    staticCodeIsValid: { staticCodeIsValid },
    runningApplicationCount: { runningApplicationCount },
    openExactApplication: {
      trace.recordOpen()
      if let openResult { return openResult }
      return .opened(
        VendorAppHandoffCandidate(
          identityIsCurrent: { trace.currentIdentity() },
          isTerminated: { trace.isTerminated },
          forceTerminateExactReceiver: { trace.forceExactReceiver() }
        ))
    }
  )
}

private func isNotLaunched(_ result: VendorAppHandoffLaunchResult) -> Bool {
  if case .notLaunched = result { return true }
  return false
}

private final class VendorAppHandoffBridgeTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedIdentityIsCurrent: Bool
  private var storedTerminated = false
  private var storedOpenCount = 0
  private var storedIdentityCheckCount = 0
  private var storedForceCount = 0

  init(identityIsCurrent: Bool = true) {
    storedIdentityIsCurrent = identityIsCurrent
  }

  func setIdentityIsCurrent(_ value: Bool) {
    lock.withLock { storedIdentityIsCurrent = value }
  }

  func currentIdentity() -> Bool {
    lock.withLock {
      storedIdentityCheckCount += 1
      return storedIdentityIsCurrent
    }
  }

  func recordOpen() {
    lock.withLock { storedOpenCount += 1 }
  }

  func forceExactReceiver() -> Bool {
    lock.withLock {
      storedForceCount += 1
      return true
    }
  }

  var isTerminated: Bool { lock.withLock { storedTerminated } }
  var openCount: Int { lock.withLock { storedOpenCount } }
  var identityCheckCount: Int { lock.withLock { storedIdentityCheckCount } }
  var forceCount: Int { lock.withLock { storedForceCount } }
}
