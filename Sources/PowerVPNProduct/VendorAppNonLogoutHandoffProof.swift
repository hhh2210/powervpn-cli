import Darwin
import Foundation
import PowerVPNCore

package struct VendorAppNonLogoutHandoffCleanupProof:
  Codable, Equatable, Sendable
{
  package let complete: Bool
  package let defaultRouteRestored: Bool
  package let dnsRestored: Bool
  package let interfacesRestored: Bool
  package let utunRestored: Bool
  package let persistentRoutesRestored: Bool
  package let surgeStateRestored: Bool
  package let vendorProcessesAbsent: Bool
  package let helperInactive: Bool
  package let structuralRouteTablesEqual: Bool

  package var allDimensionsRestored: Bool {
    complete && defaultRouteRestored && dnsRestored && interfacesRestored
      && utunRestored && persistentRoutesRestored && surgeStateRestored
      && vendorProcessesAbsent && helperInactive && structuralRouteTablesEqual
  }
}

package struct VendorAppNonLogoutHandoffPin: Codable, Equatable, Sendable {
  package let osBuild: String
  package let appVersion: String
  package let appBuild: String
  package let bundleIdentifier: String
  package let signerTeamIdentifier: String

  package static let currentMachine = Self(
    osBuild: "26A5406e",
    appVersion: "3.2.1",
    appBuild: "24572",
    bundleIdentifier: "com.leadsec.PowerVPN-Mac",
    signerTeamIdentifier: "M75ATYZ92T"
  )

  package var matchesCurrentInstalledEnvironment: Bool {
    guard self == Self.currentMachine,
      Self.currentOSBuild() == osBuild,
      let bundle = Bundle(url: URL(fileURLWithPath: SystemInspector.appPath))
    else { return false }
    return bundle.bundleIdentifier == bundleIdentifier
      && bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        == appVersion
      && bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String == appBuild
  }

  private static func currentOSBuild() -> String? {
    var count = 0
    guard sysctlbyname("kern.osversion", nil, &count, nil, 0) == 0,
      (2...64).contains(count)
    else { return nil }
    var bytes = [UInt8](repeating: 0, count: count)
    guard sysctlbyname("kern.osversion", &bytes, &count, nil, 0) == 0,
      count > 1,
      bytes[count - 1] == 0
    else { return nil }
    return String(bytes: bytes[..<(count - 1)], encoding: .utf8)
  }
}

package struct VendorAppNonLogoutHandoffProof: Codable, Equatable, Sendable {
  package static let schemaVersion = 1

  package let schema: Int
  package let assurance: String
  package let pin: VendorAppNonLogoutHandoffPin
  package let forceTerminationAccepted: Bool
  package let exactReceiverTerminated: Bool
  package let normalQuitRequested: Bool
  package let logoutRecordObserved: Bool
  package let cleanup: VendorAppNonLogoutHandoffCleanupProof
  package let finalSourceSeal: VendorAppSessionSourceSeal
  package let finalHelperRuns: Int
  package let createdAt: VendorAppCursorTimestamp

  package init(
    cleanup: VendorAppNonLogoutHandoffCleanupProof,
    finalSourceSeal: VendorAppSessionSourceSeal,
    finalHelperRuns: Int,
    createdAt: VendorAppCursorTimestamp,
    pin: VendorAppNonLogoutHandoffPin = .currentMachine
  ) {
    schema = Self.schemaVersion
    assurance = "current_machine_pinned"
    self.pin = pin
    forceTerminationAccepted = true
    exactReceiverTerminated = true
    normalQuitRequested = false
    logoutRecordObserved = false
    self.cleanup = cleanup
    self.finalSourceSeal = finalSourceSeal
    self.finalHelperRuns = finalHelperRuns
    self.createdAt = createdAt
  }

  func accepts(
    material: VendorAppSessionSnapshotMaterial,
    generation: VendorHelperGenerationSnapshot
  ) -> Bool {
    isStructurallyValid
      && pin.matchesCurrentInstalledEnvironment
      && material.sourceSeal == finalSourceSeal
      && material.sourceIsCurrent
      && generation.exactInactive
      && generation.runs == finalHelperRuns
  }

  package var isStructurallyValid: Bool {
    schema == Self.schemaVersion
      && assurance == "current_machine_pinned"
      && pin == .currentMachine
      && forceTerminationAccepted
      && exactReceiverTerminated
      && !normalQuitRequested
      && !logoutRecordObserved
      && cleanup.allDimensionsRestored
      && finalSourceSeal.isStructurallyValid
      && finalHelperRuns >= 0
  }

  package func isBound(to cursor: VendorAppOnboardingCursor) -> Bool {
    guard isStructurallyValid,
      finalSourceSeal.device == cursor.device,
      finalSourceSeal.inode == cursor.inode,
      finalSourceSeal.ownerUID == cursor.ownerUID,
      finalSourceSeal.mode == cursor.mode,
      finalSourceSeal.size >= 0,
      UInt64(finalSourceSeal.size) > cursor.size,
      UInt64(finalSourceSeal.size) - cursor.size
        <= UInt64(VendorAppSessionSnapshotSource.maximumAppendBytes),
      !Self.earlier(
        seconds: finalSourceSeal.modificationSeconds,
        nanoseconds: finalSourceSeal.modificationNanoseconds,
        than: cursor.modificationTime
      ),
      !Self.earlier(
        seconds: finalSourceSeal.changeSeconds,
        nanoseconds: finalSourceSeal.changeNanoseconds,
        than: cursor.changeTime
      ),
      !Self.earlier(
        seconds: createdAt.seconds,
        nanoseconds: Int(createdAt.nanoseconds),
        than: cursor.capturedAt
      )
    else { return false }
    return true
  }

  private static func earlier(
    seconds: Int64,
    nanoseconds: Int,
    than timestamp: VendorAppCursorTimestamp
  ) -> Bool {
    seconds < timestamp.seconds
      || (seconds == timestamp.seconds && nanoseconds < timestamp.nanoseconds)
  }
}
