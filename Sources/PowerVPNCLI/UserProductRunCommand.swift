import Foundation
import PowerVPNProduct

/// `powervpn run <target> -- <command...>` is the one-call entrypoint for agents and scripts.
///
/// It reuses the persistent session for `target`, starts one when none is active, clears a
/// cleanup quarantine only through the existing measured `recovery clear` gate, retries
/// transient start and recovery failures within fixed bounds, and then runs the command over the
/// session's ControlMaster.
/// The command itself runs without the session command lock, so several `run` calls can share
/// one session concurrently.
///
/// Exit codes: the remote command's own code once it ran; 75 retryable; 77 needs a human.
/// Every PowerVPN-side failure ends stderr with `powervpn run: <token>` and `next: <action>`,
/// which distinguishes it from a remote command that happens to exit 75 or 77.
///
/// Worst-case time `run` adds by sleeping (the injected `sleepMilliseconds`; each recovery or
/// start attempt also costs its own run time):
/// - settle (`settleLocalState`): at most 19 s per use, one use after each `up` that leaves a
///   quarantine (exit 74) and one before each vendor-helper preflight retry;
/// - recovery retries: at most 3 waits (the attempt cap is 4): 10 s after `selection_rejected`,
///   3 s after `cold_baseline_rejected`, one settle after transient vendor-helper preflight
///   findings. 41 s at most (two settles and one cold-baseline wait), 9 s for the common
///   cold-baseline flake;
/// - `local_safety_check_failed` start retries: 2 retries, each a 3 s / 6 s backoff plus one
///   settle, so 47 s at most.
enum UserProductRunExit {
  static let retryable: Int32 = 75
  static let needsHuman: Int32 = 77
}

private let runStepLimit = 40
private let runBusyWaitLimit = 30
private let runBusyWaitMilliseconds = 2_000
private let runStartRetryMilliseconds = 3_000
private let runSettlePollLimit = 20
private let runSettlePollMilliseconds = 1_000

/// Start failures that a retry cannot fix: credentials or configuration.
private let runHumanStartFailures: Set<String> = [
  "runtime_unavailable",
  NativeTunnelFailure.helperUnavailable.rawValue,
  NativeTunnelFailure.charonUnavailable.rawValue,
  NativeTunnelFailure.targetInvalid.rawValue,
  NativeTunnelFailure.portalRejected.rawValue,
  NativeTunnelFailure.resourceUnavailable.rawValue,
]

/// `local_safety_check_failed` also names transient states (the vendor helper still exiting, the
/// mutation lease briefly held), so `run` retries it with these backoffs before giving up.
private let runLocalSafetyRetryBackoffsMilliseconds = [3_000, 6_000]

func runUserProductRun(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments.count >= 4, arguments[2] == "--" else {
    throw UserProductCommandError.invalidArguments(
      "usage: powervpn run <target> -- <remote command>"
    )
  }
  let remoteCommand = Array(arguments.dropFirst(3))
  let rerun = "powervpn run \(arguments[1]) -- <same command>"

  let target: UserProductTarget
  do {
    target = try resolveUserProductTarget(arguments[1], dependencies: dependencies)
  } catch UserProductCommandError.invalidArguments(let token) {
    return runFailure(
      "target_configuration_invalid",
      "PowerVPN: target '\(arguments[1])' is not usable (\(token)).",
      exitCode: UserProductRunExit.needsHuman,
      next: "powervpn doctor --json"
    )
  }
  guard let sshConfiguration = effectiveSSHConfiguration(target: target, dependencies: dependencies)
  else {
    return runFailure(
      "ssh_config_mismatch",
      "PowerVPN: ~/.ssh/config Host '\(target.key)' does not match targets.json or lacks ControlMaster.",
      exitCode: UserProductRunExit.needsHuman,
      next:
        "fix `Host \(target.key)` in ~/.ssh/config (HostName/User as in targets.json, ControlMaster auto, ControlPath under ~/.ssh/)"
    )
  }

  var notes: [String] = []
  var recoveryAttempts = 0
  var startFailures = 0
  var localSafetyRetries = 0
  var busyWaits = 0

  func waitWhileBusy() async -> Bool {
    guard busyWaits < runBusyWaitLimit else { return false }
    busyWaits += 1
    await dependencies.sleepMilliseconds(runBusyWaitMilliseconds)
    return true
  }

  for _ in 0..<runStepLimit {
    if let state = try dependencies.stateStore.load() {
      if !state.terminal, checkMaster(state, dependencies: dependencies).exitCode == 0 {
        guard state.target == target.key else {
          return runFailure(
            "connected_to_other_target",
            "PowerVPN: a session to \(state.target) is active.",
            exitCode: UserProductRunExit.needsHuman,
            next: "powervpn down"
          )
        }
        return execute(
          state: state, target: target, remoteCommand: remoteCommand, notes: notes,
          rerun: rerun, dependencies: dependencies)
      }
      // Another process is still starting or tearing down a session: wait for it instead of
      // counting its in-flight work as our start failure.
      if !state.terminal, !dependencies.mutationLeaseAvailable() {
        if await waitWhileBusy() { continue }
        return runBusy(rerun)
      }
      // Native leftovers are cleared by `up` itself; only the vendor needs recovery.
      if state.terminal, !state.reconnectPermitted, !usesNativeBackend(dependencies) {
        guard recoveryAttempts < runRecoveryAttemptLimit else {
          return runFailure(
            "quarantine_persists",
            "PowerVPN: cleanup is still unverified after a measured recovery.",
            exitCode: UserProductRunExit.needsHuman,
            next: "powervpn recovery inspect --json"
          )
        }
        recoveryAttempts += 1
        let recovery = try await runUserProductRecovery(
          arguments: ["recovery", "clear", "--json"],
          dependencies: dependencies
        )
        switch recovery.exitCode {
        case 0:
          notes.append(
            "powervpn run: quarantine_cleared (measured cold baseline; original cleanup stays unverified)"
          )
          continue
        case 75:
          recoveryAttempts -= 1
          if await waitWhileBusy() { continue }
          return runBusy(rerun)
        default:
          let detail = recoveryRejectionDetail(recovery.standardOutput)
          // Only flaky classes are retried: the Portal catalog yielding no unique resource, two
          // back-to-back snapshots that differ while Surge's TUN churns host routes, and a
          // vendor helper that is still exiting. Persistent local preflight failures are not.
          if let retry = recoveryRetry(for: detail), recoveryAttempts < retry.maxAttempts {
            if !retry.settlesVendor {
              await dependencies.sleepMilliseconds(retry.delayMilliseconds)
              continue
            }
            if await settleLocalState(dependencies: dependencies) { continue }
          }
          return runFailure(
            "recovery_rejected",
            recoveryRejectionMessage(detail, attempts: recoveryAttempts),
            exitCode: UserProductRunExit.needsHuman,
            next: detail.nextAction ?? "powervpn recovery inspect --json"
          )
        }
      }
    } else if foreignMasterIsRunning(sshConfiguration, target: target, dependencies: dependencies) {
      return runFailure(
        "foreign_control_master",
        "PowerVPN: an SSH ControlMaster for \(target.key) exists but was not started by PowerVPN.",
        exitCode: UserProductRunExit.needsHuman,
        next: "ssh -S \(sshConfiguration.controlPath) -O exit \(target.key)"
      )
    }

    let up = try await runUserProductUp(arguments: ["up", target.key], dependencies: dependencies)
    switch up.exitCode {
    case 0:
      notes.append("powervpn run: session_started (kept for reuse; `powervpn down` stops it)")
    case 75:
      if await waitWhileBusy() { continue }
      return runBusy(rerun)
    case 74:
      // The start left a quarantine. The vendor helper crashes on every stop and stays visible
      // while the crash report is captured, so let it settle before the measured recovery.
      _ = await settleLocalState(dependencies: dependencies)
      continue
    default:
      let failure = (try? dependencies.stateStore.load())?.failure
      if let failure, runHumanStartFailures.contains(failure) {
        return runFailure(
          failure,
          firstLine(of: up.standardError),
          exitCode: UserProductRunExit.needsHuman,
          next: NativeTunnelFailure(rawValue: failure)?.next ?? "powervpn doctor --json"
        )
      }
      if failure == "local_safety_check_failed" {
        // A missing or unsafe vendor log, or a vendor process that never goes away, is not
        // transient: retry only while the log is fine and the helper settles.
        if localSafetyRetries < runLocalSafetyRetryBackoffsMilliseconds.count,
          dependencies.vendorLogFinding() == .bounded
        {
          await dependencies.sleepMilliseconds(
            runLocalSafetyRetryBackoffsMilliseconds[localSafetyRetries])
          localSafetyRetries += 1
          if await settleLocalState(dependencies: dependencies) { continue }
        }
        return runFailure(
          "local_safety_check_failed",
          firstLine(of: up.standardError),
          exitCode: UserProductRunExit.needsHuman,
          next: "powervpn doctor --json"
        )
      }
      startFailures += 1
      if startFailures < 2 {
        await dependencies.sleepMilliseconds(runStartRetryMilliseconds)
        continue
      }
      return runFailure(
        "session_start_failed",
        firstLine(of: up.standardError),
        exitCode: UserProductRunExit.retryable,
        next: "\(rerun) (if it fails again: powervpn doctor --json)"
      )
    }
  }
  return runFailure(
    "session_not_ready",
    "PowerVPN: the session did not become ready.",
    exitCode: UserProductRunExit.retryable,
    next: rerun
  )
}

private func execute(
  state: UserProductSessionState,
  target: UserProductTarget,
  remoteCommand: [String],
  notes: [String],
  rerun: String,
  dependencies: UserProductCommandDependencies
) -> UserProductCommandResult {
  let result = dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.useMaster(
      target: target.key,
      controlPath: state.controlPath,
      remoteCommand: remoteCommand
    ),
    io: .inherited
  )
  guard result.started else {
    return runFailure(
      "ssh_unavailable",
      "PowerVPN: could not start /usr/bin/ssh.",
      exitCode: UserProductRunExit.needsHuman,
      next: "check that /usr/bin/ssh runs"
    )
  }
  // 255 is OpenSSH's own failure code. If the master is gone too, the command may never
  // have reached the server, so report a retryable PowerVPN failure instead of passing 255 on.
  if result.exitCode == 255, checkMaster(state, dependencies: dependencies).exitCode != 0 {
    return runFailure(
      "session_lost",
      "PowerVPN: the session ended before or while the command ran; it may not have run.",
      exitCode: UserProductRunExit.retryable,
      next: rerun
    )
  }
  return UserProductCommandResult(
    standardOutput: "",
    standardError: notes.isEmpty ? "" : notes.joined(separator: "\n") + "\n",
    exitCode: result.exitCode
  )
}

private func foreignMasterIsRunning(
  _ configuration: UserProductSSHEffectiveConfiguration,
  target: UserProductTarget,
  dependencies: UserProductCommandDependencies
) -> Bool {
  dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.checkMaster(
      target: target.key,
      controlPath: configuration.controlPath
    ),
    io: .captured
  ).exitCode == 0
}

private func runBusy(_ rerun: String) -> UserProductCommandResult {
  runFailure(
    "command_busy",
    "PowerVPN: another session start or recovery kept running for over a minute.",
    exitCode: UserProductRunExit.retryable,
    next: rerun
  )
}

private func runFailure(
  _ token: String,
  _ message: String,
  exitCode: Int32,
  next: String
) -> UserProductCommandResult {
  UserProductCommandResult(
    standardOutput: "",
    standardError: "\(message)\npowervpn run: \(token)\nnext: \(next)\n",
    exitCode: exitCode
  )
}

private func firstLine(of text: String) -> String {
  let line = text.split(separator: "\n", omittingEmptySubsequences: true).first.map(String.init)
  return line ?? "PowerVPN: the session could not start."
}

/// Waits until no vendor process is visible, the helper is launchd-inactive and the mutation
/// lease is free, polling every second for at most `runSettlePollLimit` polls (19 s of sleeping).
/// Returns whether the local state settled; callers go on either way, because the measured
/// recovery names whatever is still wrong.
private func settleLocalState(dependencies: UserProductCommandDependencies) async -> Bool {
  for poll in 0..<runSettlePollLimit {
    if dependencies.mutationLeaseAvailable(), await dependencies.vendorQuiescent() {
      return true
    }
    if poll + 1 < runSettlePollLimit {
      await dependencies.sleepMilliseconds(runSettlePollMilliseconds)
    }
  }
  return false
}

private struct RecoveryRejectionDetail {
  let failure: String?
  let findings: [String]
  /// Names of the cold-baseline assessment dimensions that failed; values are never included.
  let failedChecks: [String]
  let nextAction: String?
}

/// Reads the value-free fields a rejected `recovery clear` reports, so `run` can name the failed
/// preflight condition or assessment dimension and its specific next step instead of a generic
/// inspect.
private func recoveryRejectionDetail(_ json: String) -> RecoveryRejectionDetail {
  guard
    let object = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
  else {
    return RecoveryRejectionDetail(failure: nil, findings: [], failedChecks: [], nextAction: nil)
  }
  let measurement = object["measurement"] as? [String: Any]
  return RecoveryRejectionDetail(
    failure: measurement?["failure"] as? String,
    findings: measurement?["preflightFindings"] as? [String] ?? [],
    failedChecks: failedAssessmentChecks(measurement?["captureAssessment"] as? [String: Any]),
    nextAction: object["nextAction"] as? String
  )
}

/// The `NetworkColdRecoveryAssessment` keys that report a failed dimension: Bool fields that are
/// false, and a selected-route residue count above zero. `passed` and the constant `contains*`
/// flags are not dimensions. Bool is told apart from the 0/1 counts through the CFBoolean type.
private func failedAssessmentChecks(_ assessment: [String: Any]?) -> [String] {
  (assessment ?? [:]).compactMap { key, value -> String? in
    guard key != "passed", !key.hasPrefix("contains"), let number = value as? NSNumber
    else { return nil }
    if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? nil : key }
    return key.hasSuffix("ResidueCount") && number.intValue > 0 ? key : nil
  }.sorted()
}

private func recoveryRejectionMessage(_ detail: RecoveryRejectionDetail, attempts: Int) -> String {
  let attemptSuffix = attempts > 1 ? " after \(attempts) attempts" : ""
  if !detail.findings.isEmpty {
    return
      "PowerVPN: local preflight failed (\(detail.findings.joined(separator: ", ")))\(attemptSuffix); reconnect stays quarantined."
  }
  let checks =
    detail.failedChecks.isEmpty ? "" : " (\(detail.failedChecks.joined(separator: ", ")))"
  return
    "PowerVPN: the measured cold-baseline check did not pass\(checks)\(attemptSuffix); reconnect stays quarantined."
}

/// Largest `RunRecoveryRetry.maxAttempts`; the quarantine loop gives up once it is reached.
private let runRecoveryAttemptLimit = 4

private struct RunRecoveryRetry {
  /// Total recovery attempts allowed for this class of rejection, counting the first one.
  let maxAttempts: Int
  let delayMilliseconds: Int
  /// Wait for the vendor helper to settle instead of sleeping `delayMilliseconds`.
  let settlesVendor: Bool
}

/// Transient vendor-process states: the helper crashes on every stop under macOS 27.2/Rosetta and
/// stays visible for several seconds. Any other finding (GUI running, DNS recovery file, vendor
/// log) needs a human or a repair, so one of those anywhere in the list rules out a retry.
private let runTransientPreflightFindings: Set<String> = [
  "vendor_helper_running",
  "vendor_helper_not_inactive",
  "vendor_auxiliary_helper_running",
]

private func recoveryRetry(for detail: RecoveryRejectionDetail) -> RunRecoveryRetry? {
  switch detail.failure {
  case "selection_rejected":
    return RunRecoveryRetry(maxAttempts: 3, delayMilliseconds: 10_000, settlesVendor: false)
  case "cold_baseline_rejected":
    // About a third of attempts fail because two back-to-back snapshots differ.
    return RunRecoveryRetry(maxAttempts: 4, delayMilliseconds: 3_000, settlesVendor: false)
  case "preflight_rejected"
  where !detail.findings.isEmpty && Set(detail.findings).isSubset(of: runTransientPreflightFindings):
    return RunRecoveryRetry(maxAttempts: 3, delayMilliseconds: 0, settlesVendor: true)
  default:
    return nil
  }
}
