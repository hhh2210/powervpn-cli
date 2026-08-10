import AppKit
import Darwin
import Foundation

package protocol BoundedVendorXPCPreflightChecking: Sendable {
  func check(
    generation: VendorHelperGenerationSnapshot
  ) async -> VendorXPCPreflightEvidence
}

package enum VendorXPCPreflightPathObservation: Equatable, Sendable {
  case absent
  case regularFile(size: UInt64)
  case unsupported
  case unavailable
}

/// Performs the installed-helper preflight without unbounded subprocesses or
/// retaining process output. Construction is inert; `check` performs exactly
/// one fixed, bounded process snapshot plus two fixed-path `lstat` inspections.
package struct InstalledBoundedVendorXPCPreflightChecker:
  BoundedVendorXPCPreflightChecking
{
  package static let dnsRecoveryPath = "/tmp/vpntmp.log"
  package static let vendorLogPath = "/var/log/vsgvpn.log"
  package static let vendorLogRotationThreshold: UInt64 = 0x1E00_000

  private let runner: any NetworkCleanupCommandRunning
  private let guiApplicationRunning: @Sendable () -> Bool
  private let inspectPath: @Sendable (String) -> VendorXPCPreflightPathObservation

  package init() {
    runner = InstalledNetworkCleanupCommandRunner()
    guiApplicationRunning = Self.installedGUIApplicationRunning
    inspectPath = Self.installedPathObservation
  }

  init(
    runner: any NetworkCleanupCommandRunning,
    guiApplicationRunning: @escaping @Sendable () -> Bool,
    inspectPath:
      @escaping @Sendable (String) -> VendorXPCPreflightPathObservation
  ) {
    self.runner = runner
    self.guiApplicationRunning = guiApplicationRunning
    self.inspectPath = inspectPath
  }

  package func check(
    generation: VendorHelperGenerationSnapshot
  ) async -> VendorXPCPreflightEvidence {
    let processResult = await runner.run(.surgeProcesses)
    let presence = Self.processPresence(processResult)
    let guiAbsent = presence.map { !$0.gui } ?? false
    let helperAbsent = presence.map { !$0.charon } ?? false
    let otherHelpersAbsent = presence.map { !$0.ipsec && !$0.shell } ?? false
    let dnsRecoveryAbsent = inspectPath(Self.dnsRecoveryPath) == .absent
    let logSafe: Bool
    switch inspectPath(Self.vendorLogPath) {
    case .absent: logSafe = true
    case .regularFile(let size): logSafe = size <= Self.vendorLogRotationThreshold
    case .unsupported, .unavailable: logSafe = false
    }
    return VendorXPCPreflightEvidence(
      guiProcessAbsent: guiAbsent && !guiApplicationRunning(),
      helperProcessAbsent: helperAbsent,
      otherVendorHelperProcessesAbsent: otherHelpersAbsent,
      helperLaunchdInactive: generation.exactInactive,
      dnsRecoveryFileAbsent: dnsRecoveryAbsent,
      vendorLogRotationSafe: logSafe
    )
  }

  private static func processPresence(
    _ result: BoundedCommandResult
  ) -> VendorXPCPreflightProcessPresence? {
    guard result.succeeded else { return nil }
    do {
      return try VendorXPCPreflightProcessParser.parse(result.stdout)
    } catch {
      return nil
    }
  }

  private static func installedGUIApplicationRunning() -> Bool {
    !NSRunningApplication.runningApplications(
      withBundleIdentifier: "com.leadsec.PowerVPN-Mac"
    ).isEmpty
  }

  private static func installedPathObservation(
    _ path: String
  ) -> VendorXPCPreflightPathObservation {
    var metadata = stat()
    errno = 0
    let result = path.withCString { lstat($0, &metadata) }
    if result == -1 {
      return errno == ENOENT ? .absent : .unavailable
    }
    guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_size >= 0 else {
      return .unsupported
    }
    return .regularFile(size: UInt64(metadata.st_size))
  }
}

private struct VendorXPCPreflightProcessPresence: Equatable, Sendable {
  var gui = false
  var charon = false
  var ipsec = false
  var shell = false
}

private enum VendorXPCPreflightProcessParser {
  private static let weekdays: Set<Substring> = [
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
  ]
  private static let months: Set<Substring> = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ]

  static func parse(_ data: Data) throws -> VendorXPCPreflightProcessPresence {
    var presence = VendorXPCPreflightProcessPresence()
    var seenPIDs: Set<Int> = []
    for rawLine in try NetworkCleanupText.lines(data) {
      let fields = rawLine.split(whereSeparator: \Character.isWhitespace)
      guard !fields.isEmpty else { continue }
      guard fields.count >= 7, let pid = Int(fields[0]), pid > 0,
        validStartFields(fields[1...5]), seenPIDs.insert(pid).inserted
      else { throw NetworkCleanupCanonicalizationError.invalidShape }
      switch executableName(String(fields[6])) {
      case "PowerVPN": presence.gui = true
      case "com.leadsec.charon-xpc": presence.charon = true
      case "com.leadsec.ipsec-xpc": presence.ipsec = true
      case "com.leadsec.sh-xpc": presence.shell = true
      default: break
      }
    }
    guard !seenPIDs.isEmpty else {
      throw NetworkCleanupCanonicalizationError.emptyInventory
    }
    return presence
  }

  private static func executableName(_ executable: String) -> String {
    URL(fileURLWithPath: executable).lastPathComponent
  }

  private static func validStartFields<C: Collection>(_ fields: C) -> Bool
  where C.Element == Substring {
    let values = Array(fields)
    guard values.count == 5, weekdays.contains(values[0]), months.contains(values[1]),
      canonicalDecimal(values[2], range: 1...31),
      canonicalDecimal(values[4], width: 4, range: 1970...9999)
    else { return false }
    let time = values[3].split(separator: ":", omittingEmptySubsequences: false)
    return time.count == 3
      && canonicalDecimal(time[0], width: 2, range: 0...23)
      && canonicalDecimal(time[1], width: 2, range: 0...59)
      && canonicalDecimal(time[2], width: 2, range: 0...59)
  }

  private static func canonicalDecimal(
    _ value: Substring,
    width: Int? = nil,
    range: ClosedRange<Int>
  ) -> Bool {
    guard width.map({ value.count == $0 }) ?? (1...2).contains(value.count),
      value.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
      let integer = Int(value), range.contains(integer)
    else { return false }
    return width != nil || String(integer) == value
  }
}
