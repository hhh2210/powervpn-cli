import Foundation
import PowerVPNCore

/// The one local precondition an agent cannot restore without root: `/var/log/vsgvpn.log`
/// must exist as an empty-or-bounded `root:wheel 0600` file before the vendor helper starts,
/// otherwise launchd recreates it world-readable. Repair asks macOS for administrator approval
/// through its native dialog; PowerVPN never sees a password.
let vendorLogRepairCommand = "powervpn repair vendor-log --json"

private let vendorLogPath = InstalledBoundedVendorXPCPreflightChecker.vendorLogPath

/// `set -C` makes the create fail instead of truncating a file that appeared after the check.
private let createVendorLogScript =
  "set -C; umask 077; : > \(vendorLogPath)"
  + " && /usr/sbin/chown root:wheel \(vendorLogPath) && /bin/chmod 0600 \(vendorLogPath)"
private let tightenVendorLogScript =
  "/usr/sbin/chown root:wheel \(vendorLogPath) && /bin/chmod 0600 \(vendorLogPath)"

private struct UserProductRepairReport: Encodable {
  let schemaVersion = 1
  let operation = "repair"
  let item = "vendor_log"
  let outcome: String
  let findingBefore: VendorLogFinding?
  let findingAfter: VendorLogFinding?
  let administratorApprovalRequested: Bool
  let requiresHumanAction: Bool
  let nextAction: String?
  let containsSecrets = false
}

func vendorLogBlocker(_ finding: VendorLogFinding) -> String {
  switch finding {
  case .bounded: "none"
  case .absent: "vendor_log_absent"
  case .oversized: "vendor_log_oversized"
  case .unsafeOwnership, .unsafePermissions: "vendor_log_permissions_unsafe"
  case .unsupported, .unavailable: "vendor_log_unavailable"
  }
}

func runUserProductRepair(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments == ["repair", "vendor-log", "--json"] else {
    throw UserProductCommandError.invalidArguments("usage: powervpn repair vendor-log --json")
  }

  let commandLock: UserProductSessionCommandLock
  do {
    commandLock = try dependencies.stateStore.acquireCommandLock()
  } catch UserProductSessionStoreError.busy {
    return try repairResult(outcome: "command_busy", requiresHumanAction: false, exitCode: 75)
  }
  defer { withExtendedLifetime(commandLock) {} }

  let before = dependencies.vendorLogFinding()
  if before == .bounded {
    return try repairResult(
      outcome: "not_required",
      before: before,
      after: before,
      requiresHumanAction: false,
      exitCode: 0
    )
  }
  guard before.repairable else {
    // Oversized or non-regular logs can only be fixed by discarding vendor data; leave that
    // decision to Larry.
    return try repairResult(
      outcome: "not_repairable",
      before: before,
      requiresHumanAction: true,
      exitCode: 74
    )
  }
  // Never touch the log while a session could be starting or the vendor helper could write it.
  if let state = try dependencies.stateStore.load(), !state.terminal {
    return try repairResult(
      outcome: "session_active",
      before: before,
      requiresHumanAction: false,
      exitCode: 75
    )
  }
  guard dependencies.mutationLeaseAvailable(), await dependencies.vendorQuiescent() else {
    return try repairResult(
      outcome: "vendor_busy",
      before: before,
      requiresHumanAction: false,
      exitCode: 75
    )
  }

  let script = before == .absent ? createVendorLogScript : tightenVendorLogScript
  let approval = dependencies.processRunner.run(
    executable: "/usr/bin/osascript",
    arguments: [
      "-e",
      "do shell script \"\(script)\" with administrator privileges"
        + " with prompt \"PowerVPN needs to restore its root-only vendor log.\"",
    ],
    io: .captured
  )
  let after = dependencies.vendorLogFinding()
  if after == .bounded {
    return try repairResult(
      outcome: "repaired",
      before: before,
      after: after,
      approvalRequested: true,
      requiresHumanAction: false,
      nextAction: "powervpn recovery clear --json",
      exitCode: 0
    )
  }
  return try repairResult(
    outcome: approval.started && approval.exitCode == 0
      ? "repair_unverified" : "approval_not_granted",
    before: before,
    after: after,
    approvalRequested: approval.started,
    requiresHumanAction: true,
    nextAction: vendorLogRepairCommand,
    exitCode: 77
  )
}

private func repairResult(
  outcome: String,
  before: VendorLogFinding? = nil,
  after: VendorLogFinding? = nil,
  approvalRequested: Bool = false,
  requiresHumanAction: Bool,
  nextAction: String? = nil,
  exitCode: Int32
) throws -> UserProductCommandResult {
  let report = UserProductRepairReport(
    outcome: outcome,
    findingBefore: before,
    findingAfter: after,
    administratorApprovalRequested: approvalRequested,
    requiresHumanAction: requiresHumanAction,
    nextAction: nextAction
  )
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  return UserProductCommandResult(
    standardOutput: String(decoding: try encoder.encode(report), as: UTF8.self) + "\n",
    standardError: "",
    exitCode: exitCode
  )
}
