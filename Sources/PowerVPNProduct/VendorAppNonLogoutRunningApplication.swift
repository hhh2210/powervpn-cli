import AppKit
import Darwin
import Foundation
import Security

package protocol VendorAppHandoffApplication: AnyObject, Sendable {
  var identityIsCurrent: Bool { get }
  var isTerminated: Bool { get }
  func forceTerminate() -> Bool
}

package enum VendorAppHandoffLaunchResult: Sendable {
  case notLaunched
  case ready(any VendorAppHandoffApplication)
  case launchedButUnusable(stillRunning: @Sendable () -> Bool)
}

package protocol VendorAppHandoffLaunching: Sendable {
  func launch() async -> VendorAppHandoffLaunchResult
}

/// Current-machine-only LaunchServices bridge. The only termination mutation
/// retained by the returned handle is `forceTerminate()` on the exact receiver
/// returned by `NSWorkspace`; there is deliberately no PID, normal-quit, or
/// rediscovery fallback.
package struct InstalledVendorAppHandoffLauncher: VendorAppHandoffLaunching {
  private let dependencies: VendorAppHandoffLaunchDependencies

  package init() {
    dependencies = .installed
  }

  init(dependencies: VendorAppHandoffLaunchDependencies) {
    self.dependencies = dependencies
  }

  package func launch() async -> VendorAppHandoffLaunchResult {
    guard dependencies.systemIdentity() == .required,
      dependencies.bundleIdentity() == .required,
      dependencies.staticCodeIsValid(),
      dependencies.runningApplicationCount() == 0
    else { return .notLaunched }

    switch await dependencies.openExactApplication() {
    case .notLaunched:
      return .notLaunched
    case .launchedButUnusable(let stillRunning):
      return .launchedButUnusable(stillRunning: stillRunning)
    case .opened(let candidate):
      guard candidate.identityIsCurrent() else {
        return .launchedButUnusable(stillRunning: { !candidate.isTerminated() })
      }
      return .ready(VendorAppNonLogoutRunningApplication(candidate: candidate))
    }
  }
}

private final class VendorAppNonLogoutRunningApplication:
  VendorAppHandoffApplication,
  @unchecked Sendable
{
  private let candidate: VendorAppHandoffCandidate

  init(candidate: VendorAppHandoffCandidate) {
    self.candidate = candidate
  }

  var identityIsCurrent: Bool {
    candidate.identityIsCurrent()
  }

  var isTerminated: Bool {
    candidate.isTerminated()
  }

  func forceTerminate() -> Bool {
    guard candidate.identityIsCurrent() else { return false }
    return candidate.forceTerminateExactReceiver()
  }
}

struct VendorAppHandoffSystemIdentity: Equatable, Sendable {
  let productVersion: String
  let buildVersion: String

  static let required = Self(productVersion: "27.0", buildVersion: "26A5406e")
}

struct VendorAppHandoffBundleIdentity: Equatable, Sendable {
  let bundleIdentifier: String
  let bundlePath: String
  let executablePath: String
  let shortVersion: String
  let buildVersion: String
  let executableArchitectures: [Int]

  static let required = Self(
    bundleIdentifier: VendorAppHandoffInstalledFacts.bundleIdentifier,
    bundlePath: VendorAppHandoffInstalledFacts.bundlePath,
    executablePath: VendorAppHandoffInstalledFacts.executablePath,
    shortVersion: "3.2.1",
    buildVersion: "24572",
    executableArchitectures: [NSBundleExecutableArchitectureX86_64]
  )
}

struct VendorAppHandoffCandidate: Sendable {
  let identityIsCurrent: @Sendable () -> Bool
  let isTerminated: @Sendable () -> Bool
  let forceTerminateExactReceiver: @Sendable () -> Bool
}

enum VendorAppHandoffOpenResult: Sendable {
  case notLaunched
  case opened(VendorAppHandoffCandidate)
  case launchedButUnusable(stillRunning: @Sendable () -> Bool)
}

struct VendorAppHandoffLaunchDependencies: Sendable {
  let systemIdentity: @Sendable () -> VendorAppHandoffSystemIdentity?
  let bundleIdentity: @Sendable () -> VendorAppHandoffBundleIdentity?
  let staticCodeIsValid: @Sendable () -> Bool
  let runningApplicationCount: @Sendable () -> Int
  let openExactApplication: @Sendable () async -> VendorAppHandoffOpenResult
}

private enum VendorAppHandoffInstalledFacts {
  static let bundleIdentifier = "com.leadsec.PowerVPN-Mac"
  static let bundlePath = "/Applications/PowerVPN.app"
  static let executablePath = "/Applications/PowerVPN.app/Contents/MacOS/PowerVPN"
  static let signingRequirement =
    #"identifier "com.leadsec.PowerVPN-Mac" and anchor apple generic and certificate leaf[subject.OU] = "M75ATYZ92T" and cdhash H"4e0d443652680f85a4e028123eb92d3117a550b0""#
}

extension VendorAppHandoffLaunchDependencies {
  fileprivate static let installed = Self(
    systemIdentity: VendorAppHandoffInstalledRuntime.systemIdentity,
    bundleIdentity: VendorAppHandoffInstalledRuntime.bundleIdentity,
    staticCodeIsValid: VendorAppHandoffInstalledRuntime.staticCodeIsValid,
    runningApplicationCount: {
      NSRunningApplication.runningApplications(
        withBundleIdentifier: VendorAppHandoffInstalledFacts.bundleIdentifier
      ).count
    },
    openExactApplication: VendorAppHandoffInstalledRuntime.openExactApplication
  )
}

private enum VendorAppHandoffInstalledRuntime {
  static func systemIdentity() -> VendorAppHandoffSystemIdentity? {
    guard let productVersion = sysctlString("kern.osproductversion"),
      let buildVersion = sysctlString("kern.osversion")
    else { return nil }
    return .init(productVersion: productVersion, buildVersion: buildVersion)
  }

  static func bundleIdentity() -> VendorAppHandoffBundleIdentity? {
    let bundleURL = URL(fileURLWithPath: VendorAppHandoffInstalledFacts.bundlePath)
    guard let bundle = Bundle(url: bundleURL),
      let executableURL = bundle.executableURL,
      let shortVersion = bundle.object(
        forInfoDictionaryKey: "CFBundleShortVersionString"
      ) as? String,
      let buildVersion = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
      let architectures = bundle.executableArchitectures
    else { return nil }

    return .init(
      bundleIdentifier: bundle.bundleIdentifier ?? "",
      bundlePath: bundle.bundleURL.standardizedFileURL.path,
      executablePath: executableURL.standardizedFileURL.path,
      shortVersion: shortVersion,
      buildVersion: buildVersion,
      executableArchitectures: architectures.map(\.intValue)
    )
  }

  static func staticCodeIsValid() -> Bool {
    let bundleURL = URL(fileURLWithPath: VendorAppHandoffInstalledFacts.bundlePath)
    var staticCode: SecStaticCode?
    guard SecStaticCodeCreateWithPath(bundleURL as CFURL, [], &staticCode) == errSecSuccess,
      let staticCode
    else { return false }

    var requirement: SecRequirement?
    guard
      SecRequirementCreateWithString(
        VendorAppHandoffInstalledFacts.signingRequirement as CFString,
        [],
        &requirement
      ) == errSecSuccess,
      let requirement
    else { return false }

    // Public Security flags: all architectures, nested code, strict bundle validation.
    let flags = SecCSFlags(rawValue: (1 << 0) | (1 << 3) | (1 << 4))
    return SecStaticCodeCheckValidity(staticCode, flags, requirement) == errSecSuccess
  }

  static func openExactApplication() async -> VendorAppHandoffOpenResult {
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = true
    configuration.createsNewApplicationInstance = true
    configuration.allowsRunningApplicationSubstitution = false

    return await withCheckedContinuation { continuation in
      NSWorkspace.shared.openApplication(
        at: URL(fileURLWithPath: VendorAppHandoffInstalledFacts.bundlePath),
        configuration: configuration
      ) { application, error in
        guard error == nil, let application else {
          continuation.resume(returning: .notLaunched)
          return
        }
        let stillRunning: @Sendable () -> Bool = { !application.isTerminated }
        guard let seal = receiverSeal(application) else {
          continuation.resume(returning: .launchedButUnusable(stillRunning: stillRunning))
          return
        }
        continuation.resume(
          returning: .opened(
            VendorAppHandoffCandidate(
              identityIsCurrent: {
                receiverIdentityIsCurrent(application, seal: seal)
              },
              isTerminated: { application.isTerminated },
              forceTerminateExactReceiver: { application.forceTerminate() }
            )))
      }
    }
  }

  private struct ReceiverSeal: Equatable, Sendable {
    let processIdentifier: pid_t
    let launchDate: Date
    let bundleIdentifier: String
    let bundlePath: String
    let executablePath: String
    let executableArchitecture: Int
  }

  private static func receiverSeal(_ application: NSRunningApplication) -> ReceiverSeal? {
    guard application.processIdentifier > 1,
      application.processIdentifier != getpid(),
      let launchDate = application.launchDate,
      let bundleIdentifier = application.bundleIdentifier,
      let bundlePath = application.bundleURL?.standardizedFileURL.path,
      let executablePath = application.executableURL?.standardizedFileURL.path
    else { return nil }
    let seal = ReceiverSeal(
      processIdentifier: application.processIdentifier,
      launchDate: launchDate,
      bundleIdentifier: bundleIdentifier,
      bundlePath: bundlePath,
      executablePath: executablePath,
      executableArchitecture: application.executableArchitecture
    )
    guard seal.bundleIdentifier == VendorAppHandoffInstalledFacts.bundleIdentifier,
      seal.bundlePath == VendorAppHandoffInstalledFacts.bundlePath,
      seal.executablePath == VendorAppHandoffInstalledFacts.executablePath,
      seal.executableArchitecture == NSBundleExecutableArchitectureX86_64
    else { return nil }
    return seal
  }

  private static func receiverIdentityIsCurrent(
    _ application: NSRunningApplication,
    seal: ReceiverSeal
  ) -> Bool {
    guard !application.isTerminated,
      receiverSeal(application) == seal,
      systemIdentity() == .required,
      bundleIdentity() == .required,
      staticCodeIsValid(),
      let current = NSRunningApplication(processIdentifier: seal.processIdentifier),
      current.isEqual(application)
    else { return false }

    let matching = NSRunningApplication.runningApplications(
      withBundleIdentifier: VendorAppHandoffInstalledFacts.bundleIdentifier
    )
    return matching.count == 1 && matching[0].isEqual(application)
  }

  private static func sysctlString(_ name: String) -> String? {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, (2...128).contains(size) else {
      return nil
    }
    var bytes = [UInt8](repeating: 0, count: size)
    guard sysctlbyname(name, &bytes, &size, nil, 0) == 0,
      size > 1,
      bytes[size - 1] == 0
    else { return nil }
    return String(bytes: bytes[..<(size - 1)], encoding: .utf8)
  }
}
