import AppKit
import Darwin
import Foundation

public struct VendorHelperGenerationSnapshot: Equatable, Sendable {
  public let launchdObserved: Bool
  public let running: Bool
  public let inactiveConfirmed: Bool
  public let activeCount: Int?
  public let pid: Int?
  public let runs: Int?

  public init(
    launchdObserved: Bool,
    running: Bool,
    inactiveConfirmed: Bool,
    activeCount: Int?,
    pid: Int?,
    runs: Int?
  ) {
    self.launchdObserved = launchdObserved
    self.running = running
    self.inactiveConfirmed = inactiveConfirmed
    self.activeCount = activeCount
    self.pid = pid
    self.runs = runs
  }
  var exactInactive: Bool {
    launchdObserved && inactiveConfirmed && !running
      && activeCount == 0 && pid == nil && runs != nil
  }
  var exactRunning: Bool {
    launchdObserved && !inactiveConfirmed && running
      && activeCount.map { $0 > 0 } == true
      && pid.map { $0 > 0 } == true && runs != nil
  }
  fileprivate static let unavailable = Self(
    launchdObserved: false,
    running: false,
    inactiveConfirmed: false,
    activeCount: nil,
    pid: nil,
    runs: nil
  )
}

public protocol VendorHelperGenerationObserving: Sendable {
  func observe() -> VendorHelperGenerationSnapshot
}

public struct LaunchdVendorHelperGenerationObserver: VendorHelperGenerationObserving {
  public static let helperLabel = "system/com.leadsec.charon-xpc"

  private let runner: CommandRunner

  public init(runner: CommandRunner = CommandRunner()) {
    self.runner = runner
  }

  public func observe() -> VendorHelperGenerationSnapshot {
    guard
      let output = try? runner.run("/bin/launchctl", ["print", Self.helperLabel])
    else { return .unavailable }
    return LaunchdVendorHelperSnapshotParser.parse(output)
  }
}

enum LaunchdVendorHelperSnapshotParser {
  private static let header = "system/com.leadsec.charon-xpc = {"
  private static let keys = ["active count", "runs", "state", "pid"]

  static func parse(_ output: String) -> VendorHelperGenerationSnapshot {
    var depth = 0
    var rootSeen = false
    var rootClosed = false
    var values: [String: [String]] = [:]
    for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
      let line = String(rawLine)
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      if rootClosed, !trimmed.isEmpty { return .unavailable }
      let opens = line.utf8.count { $0 == 0x7B }
      let closes = line.utf8.count { $0 == 0x7D }
      if depth == 0, !rootSeen, opens == 0, !trimmed.isEmpty {
        return .unavailable
      }
      if depth == 0, opens > 0 {
        guard !rootSeen, trimmed == header, opens == 1, closes == 0 else {
          return .unavailable
        }
        rootSeen = true
      } else if depth == 1 {
        for key in keys {
          let prefix = "\(key) = "
          if trimmed.hasPrefix(prefix) {
            values[key, default: []].append(String(trimmed.dropFirst(prefix.count)))
          }
        }
      }
      depth += opens - closes
      guard depth >= 0 else { return .unavailable }
      if rootSeen, depth == 0 { rootClosed = true }
    }
    guard rootSeen, rootClosed,
      let activeValues = values["active count"], activeValues.count == 1,
      let active = Int(activeValues[0]), active >= 0,
      let runValues = values["runs"], runValues.count == 1,
      let runs = Int(runValues[0]), runs >= 0,
      let stateValues = values["state"], stateValues.count == 1
    else { return .unavailable }
    let pidValues = values["pid"] ?? []
    guard pidValues.count <= 1 else { return .unavailable }
    let pid = pidValues.first.flatMap(Int.init)
    if active == 0, stateValues[0] == "not running", pidValues.isEmpty {
      return .init(
        launchdObserved: true, running: false, inactiveConfirmed: true,
        activeCount: active, pid: nil, runs: runs)
    }
    if active > 0, stateValues[0] == "running", let pid, pid > 0 {
      return .init(
        launchdObserved: true, running: true, inactiveConfirmed: false,
        activeCount: active, pid: pid, runs: runs)
    }
    return .unavailable
  }
}

public enum VendorHelperGenerationRelation: String, Codable, Sendable {
  case stable
  case launched
  case launchedAndExited = "launched_and_exited"
  case changed
  case inactive
  case unavailable
}

public struct VendorHelperGenerationAssessment: Equatable, Sendable {
  public let relation: VendorHelperGenerationRelation
  public let replyPeerMatchesObservedGeneration: Bool

  public init(
    relation: VendorHelperGenerationRelation,
    replyPeerMatchesObservedGeneration: Bool
  ) {
    self.relation = relation
    self.replyPeerMatchesObservedGeneration = replyPeerMatchesObservedGeneration
  }

  public static func assess(
    before: VendorHelperGenerationSnapshot,
    after: VendorHelperGenerationSnapshot,
    replyPeerGenerationValidated: Bool
  ) -> Self {
    guard before.exactInactive || before.exactRunning,
      after.exactInactive || after.exactRunning
    else {
      return Self(relation: .unavailable, replyPeerMatchesObservedGeneration: false)
    }

    let singleRunAdvanced: Bool
    if let beforeRuns = before.runs, let afterRuns = after.runs {
      singleRunAdvanced = beforeRuns < Int.max && afterRuns == beforeRuns + 1
    } else {
      singleRunAdvanced = false
    }
    let launchedAndExited = !before.running && !after.running && singleRunAdvanced

    let relation: VendorHelperGenerationRelation
    if before.exactInactive, after.exactRunning, singleRunAdvanced {
      relation = .launched
    } else if launchedAndExited {
      relation = .launchedAndExited
    } else if before.running, after.running,
      before.pid == after.pid, before.runs == after.runs
    {
      relation = .stable
    } else if !before.running, !after.running, before.runs == after.runs {
      relation = .inactive
    } else {
      relation = .changed
    }

    let peerMatches =
      replyPeerGenerationValidated
      && (relation == .launched || relation == .launchedAndExited)
    return Self(
      relation: relation,
      replyPeerMatchesObservedGeneration: peerMatches
    )
  }
}

public struct VendorXPCPreflightEvidence: Codable, Equatable, Sendable {
  public let guiProcessAbsent: Bool
  public let helperProcessAbsent: Bool
  public let otherVendorHelperProcessesAbsent: Bool
  public let helperLaunchdInactive: Bool
  public let dnsRecoveryFileAbsent: Bool
  public let vendorLogRotationSafe: Bool

  public init(
    guiProcessAbsent: Bool,
    helperProcessAbsent: Bool,
    otherVendorHelperProcessesAbsent: Bool,
    helperLaunchdInactive: Bool,
    dnsRecoveryFileAbsent: Bool,
    vendorLogRotationSafe: Bool
  ) {
    self.guiProcessAbsent = guiProcessAbsent
    self.helperProcessAbsent = helperProcessAbsent
    self.otherVendorHelperProcessesAbsent = otherVendorHelperProcessesAbsent
    self.helperLaunchdInactive = helperLaunchdInactive
    self.dnsRecoveryFileAbsent = dnsRecoveryFileAbsent
    self.vendorLogRotationSafe = vendorLogRotationSafe
  }

  public var safeToProbe: Bool {
    guiProcessAbsent && helperProcessAbsent && otherVendorHelperProcessesAbsent
      && helperLaunchdInactive
      && dnsRecoveryFileAbsent && vendorLogRotationSafe
  }
}

public protocol VendorXPCPreflightChecking: Sendable {
  func check(
    generation: VendorHelperGenerationSnapshot
  ) -> VendorXPCPreflightEvidence
}

public struct InstalledVendorXPCPreflightChecker: VendorXPCPreflightChecking {
  private static let appBundleIdentifier = "com.leadsec.PowerVPN-Mac"
  private static let appProcessName = "PowerVPN"
  private static let helperProcessName = "com.leadsec.charon-xpc"
  private static let otherVendorHelperProcessNames = [
    "com.leadsec.ipsec-xpc", "com.leadsec.sh-xpc",
  ]
  private static let dnsRecoveryPath = "/tmp/vpntmp.log"
  private static let vendorLogPath = "/var/log/vsgvpn.log"
  private static let vendorLogRotationThreshold: off_t = 0x1E00_000

  private let runner: CommandRunner

  public init(runner: CommandRunner = CommandRunner()) {
    self.runner = runner
  }

  public func check(
    generation: VendorHelperGenerationSnapshot
  ) -> VendorXPCPreflightEvidence {
    let appAbsent =
      NSRunningApplication.runningApplications(
        withBundleIdentifier: Self.appBundleIdentifier
      ).isEmpty && processIsAbsent(named: Self.appProcessName)
    return VendorXPCPreflightEvidence(
      guiProcessAbsent: appAbsent,
      helperProcessAbsent: processIsAbsent(named: Self.helperProcessName),
      otherVendorHelperProcessesAbsent: Self.otherVendorHelperProcessNames.allSatisfy {
        processIsAbsent(named: $0)
      },
      helperLaunchdInactive: generation.exactInactive,
      dnsRecoveryFileAbsent: pathIsAbsent(Self.dnsRecoveryPath),
      vendorLogRotationSafe: regularFileIsAbsentOrBounded(
        Self.vendorLogPath,
        maximumSize: Self.vendorLogRotationThreshold
      )
    )
  }

  private func processIsAbsent(named name: String) -> Bool {
    do {
      let output = try runner.run("/usr/bin/pgrep", ["-x", name])
      return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    } catch CommandError.failed(_, let status, _) where status == 1 {
      return true
    } catch {
      return false
    }
  }

  private func pathIsAbsent(_ path: String) -> Bool {
    var metadata = stat()
    errno = 0
    let result = path.withCString { lstat($0, &metadata) }
    return result == -1 && errno == ENOENT
  }

  private func regularFileIsAbsentOrBounded(
    _ path: String,
    maximumSize: off_t
  ) -> Bool {
    var metadata = stat()
    errno = 0
    let result = path.withCString { lstat($0, &metadata) }
    if result == -1 {
      return errno == ENOENT
    }
    return metadata.st_mode & S_IFMT == S_IFREG
      && metadata.st_size <= maximumSize
  }
}
