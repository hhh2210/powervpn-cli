import Foundation

/// `powervpn run <target> -- <command...>` is the one-call entrypoint for agents and scripts.
///
/// It reuses the persistent session for `target`, starts one when none is active, clears a
/// cleanup quarantine only through the existing measured `recovery clear` gate, retries one
/// transient start failure, and then runs the command over the session's ControlMaster.
/// The command itself runs without the session command lock, so several `run` calls can share
/// one session concurrently.
///
/// Exit codes: the remote command's own code once it ran; 75 retryable; 77 needs a human.
/// Every PowerVPN-side failure ends stderr with `powervpn run: <token>` and `next: <action>`,
/// which distinguishes it from a remote command that happens to exit 75 or 77.
enum UserProductRunExit {
  static let retryable: Int32 = 75
  static let needsHuman: Int32 = 77
}

private let runStepLimit = 40
private let runBusyWaitLimit = 30
private let runBusyWaitMilliseconds = 2_000
private let runStartRetryMilliseconds = 3_000

/// Start failures that a retry cannot fix: credentials/configuration or a local safety gate.
private let runHumanStartFailures: Set<String> = [
  "local_safety_check_failed",
  "runtime_unavailable",
]

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
  var recoveryAttempted = false
  var startFailures = 0
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
      if state.terminal, !state.reconnectPermitted {
        guard !recoveryAttempted else {
          return runFailure(
            "quarantine_persists",
            "PowerVPN: cleanup is still unverified after one measured recovery.",
            exitCode: UserProductRunExit.needsHuman,
            next: "powervpn recovery inspect --json"
          )
        }
        recoveryAttempted = true
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
          recoveryAttempted = false
          if await waitWhileBusy() { continue }
          return runBusy(rerun)
        default:
          return runFailure(
            "recovery_rejected",
            "PowerVPN: the measured cold-baseline check did not pass; reconnect stays quarantined.",
            exitCode: UserProductRunExit.needsHuman,
            next: "powervpn recovery inspect --json"
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
      continue  // The start left a quarantine; the next pass runs the measured recovery once.
    default:
      if let failure = try? dependencies.stateStore.load()?.failure,
        runHumanStartFailures.contains(failure)
      {
        return runFailure(
          failure,
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
