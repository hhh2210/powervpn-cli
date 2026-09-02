import Darwin
import Foundation
import PowerVPNCore
import PowerVPNPortal
import PowerVPNProduct

enum UserProductCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments(String)

  var description: String {
    switch self {
    case .invalidArguments(let usage): usage
    }
  }
}

struct UserProductCommandResult: Equatable, Sendable {
  let standardOutput: String
  let standardError: String
  let exitCode: Int32

  static func success(_ output: String = "") -> Self {
    Self(standardOutput: output, standardError: "", exitCode: 0)
  }

  static func failure(_ error: String, exitCode: Int32 = 69) -> Self {
    Self(standardOutput: "", standardError: error + "\n", exitCode: exitCode)
  }
}

struct UserProductCommandDependencies: Sendable {
  let loadConfiguration: @Sendable () throws -> PowerVPNTargetsConfiguration
  let processRunner: any UserProductProcessRunning
  let stateStore: UserProductSessionStateStore
  let executablePath: String
  let mutationLeaseAvailable: @Sendable () -> Bool
  let systemStatus: @Sendable () -> PowerVPNStatus
  let proxyRunner: @Sendable ([String]) async throws -> ProxyCommandResult
  let sleepMilliseconds: @Sendable (Int) async -> Void
  let cleanupPollLimit: Int

  init(
    loadConfiguration: @escaping @Sendable () throws -> PowerVPNTargetsConfiguration = {
      try PowerVPNTargetsConfiguration.currentMachine()
    },
    processRunner: any UserProductProcessRunning = FoundationUserProductProcessRunner(),
    stateStore: UserProductSessionStateStore = UserProductSessionStateStore(),
    executablePath: String = UserProductCommandDependencies.currentExecutablePath,
    mutationLeaseAvailable: @escaping @Sendable () -> Bool = {
      do {
        let lease = try ProductMutationLease.acquireCurrentMachine()
        withExtendedLifetime(lease) {}
        return true
      } catch {
        return false
      }
    },
    systemStatus: @escaping @Sendable () -> PowerVPNStatus = {
      SystemInspector().status()
    },
    proxyRunner: @escaping @Sendable ([String]) async throws -> ProxyCommandResult = {
      try await runCurrentMachineProxyCommand($0)
    },
    sleepMilliseconds: @escaping @Sendable (Int) async -> Void = { milliseconds in
      try? await Task.sleep(for: .milliseconds(milliseconds))
    },
    cleanupPollLimit: Int = 140
  ) {
    self.loadConfiguration = loadConfiguration
    self.processRunner = processRunner
    self.stateStore = stateStore
    self.executablePath = executablePath
    self.mutationLeaseAvailable = mutationLeaseAvailable
    self.systemStatus = systemStatus
    self.proxyRunner = proxyRunner
    self.sleepMilliseconds = sleepMilliseconds
    self.cleanupPollLimit = cleanupPollLimit
  }

  private static var currentExecutablePath: String {
    if let path = Bundle.main.executableURL?.path, path.hasPrefix("/") { return path }
    let argument = CommandLine.arguments[0]
    if argument.hasPrefix("/") { return argument }
    return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
      .appendingPathComponent(argument).standardized.path
  }
}

private struct UserProductTarget: Sendable {
  let key: String
  let host: String
  let user: String
  let resource: String
}

private enum UserProductConnectionState: String, Encodable {
  case disconnected
  case connecting
  case connected
  case disconnecting
  case cleanupFailed = "cleanup_failed"
}

private struct UserProductStatusReport: Encodable {
  let schemaVersion = 1
  let state: UserProductConnectionState
  let target: String?
  let sessionActive: Bool
  let ownerPID: Int?
  let thuReady: Bool
  let warning: String?
  let containsSecrets = false
}

private struct UserProductDoctorReport: Encodable {
  let schemaVersion = 1
  let ready: Bool
  let targetConfigurationSafe: Bool
  let credentialFileSafe: Bool
  let helperInstalled: Bool
  let vendorLogSafe: Bool
  let sessionCleanupSafe: Bool
  let blocker: String?
  let warning: String?
  let containsSecrets = false
}

func runCurrentMachineUserProductCommand(
  _ arguments: [String],
  dependencies: UserProductCommandDependencies = UserProductCommandDependencies()
) async throws -> UserProductCommandResult {
  guard let command = arguments.first else {
    return try await runUserProductStatus(arguments: ["status"], dependencies: dependencies)
  }
  switch command {
  case "ssh":
    return try await runUserProductSSH(arguments: arguments, dependencies: dependencies)
  case "up":
    return try await runUserProductUp(arguments: arguments, dependencies: dependencies)
  case "down":
    return try await runUserProductDown(arguments: arguments, dependencies: dependencies)
  case "status":
    return try await runUserProductStatus(arguments: arguments, dependencies: dependencies)
  case "doctor":
    return try runUserProductDoctor(arguments: arguments, dependencies: dependencies)
  case "internal-proxy":
    return try await runInternalProductProxy(
      arguments: arguments,
      sessionID: nil,
      dependencies: dependencies
    )
  case "internal-session-proxy":
    guard arguments.count == 5,
      UUID(uuidString: arguments[1]) != nil
    else {
      throw UserProductCommandError.invalidArguments("internal command rejected")
    }
    return try await runInternalProductProxy(
      arguments: [arguments[0], arguments[2], arguments[3], arguments[4]],
      sessionID: arguments[1],
      dependencies: dependencies
    )
  default:
    throw UserProductCommandError.invalidArguments("unknown product command: \(command)")
  }
}

private func runUserProductSSH(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments.count >= 2 else {
    throw UserProductCommandError.invalidArguments(
      "usage: powervpn ssh <target> [-- <remote command>]"
    )
  }
  let remoteCommand: [String]
  if arguments.count == 2 {
    remoteCommand = []
  } else {
    guard arguments[2] == "--", arguments.count >= 4 else {
      throw UserProductCommandError.invalidArguments(
        "usage: powervpn ssh <target> [-- <remote command>]"
      )
    }
    remoteCommand = Array(arguments.dropFirst(3))
  }
  let target = try resolveUserProductTarget(arguments[1], dependencies: dependencies)
  let commandLock: UserProductSessionCommandLock
  do {
    commandLock = try dependencies.stateStore.acquireCommandLock()
  } catch UserProductSessionStoreError.busy {
    return .failure("PowerVPN: another session command is already running.", exitCode: 75)
  }
  defer { withExtendedLifetime(commandLock) {} }

  if let existing = try dependencies.stateStore.load() {
    if checkMaster(existing, dependencies: dependencies).exitCode == 0 {
      guard existing.target == target.key else {
        return .failure(
          "PowerVPN: already connected to \(existing.target). Run `powervpn down` first."
        )
      }
      let result = dependencies.processRunner.run(
        executable: "/usr/bin/ssh",
        arguments: UserProductSSHArguments.useMaster(
          target: target.key,
          controlPath: existing.controlPath,
          remoteCommand: remoteCommand
        ),
        io: .inherited
      )
      return result.started
        ? UserProductCommandResult(
          standardOutput: "", standardError: "", exitCode: result.exitCode)
        : .failure("PowerVPN: could not start /usr/bin/ssh.", exitCode: 70)
    }
    if existing.terminal, existing.cleanupVerified == true {
      _ = try dependencies.stateStore.remove(sessionID: existing.sessionID)
    } else {
      return .failure(
        "PowerVPN: another session is starting, cleaning up, or quarantined. Run `powervpn status`."
      )
    }
  }

  let sessionID = UUID().uuidString.lowercased()
  try dependencies.stateStore.save(
    UserProductSessionState(
      sessionID: sessionID,
      target: target.key,
      controlPath: dependencies.stateStore.directory
        .appendingPathComponent("ephemeral-\(sessionID).sock").path,
      phase: .connecting
    )
  )
  let result = dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.ephemeral(
      target: target.key,
      executablePath: dependencies.executablePath,
      sessionID: sessionID,
      remoteCommand: remoteCommand
    ),
    io: .inherited
  )
  guard result.started else {
    _ = try dependencies.stateStore.remove(sessionID: sessionID)
    return .failure("PowerVPN: could not start /usr/bin/ssh.", exitCode: 70)
  }
  _ = try dependencies.stateStore.update(sessionID: sessionID) {
    if $0.phase == .connecting { $0.phase = .disconnecting }
  }
  if let final = await waitForSessionReceipt(sessionID: sessionID, dependencies: dependencies) {
    if final.cleanupVerified == true {
      _ = try dependencies.stateStore.remove(sessionID: sessionID)
      return UserProductCommandResult(
        standardOutput: "",
        standardError: "",
        exitCode: result.exitCode
      )
    }
    return .failure(userProductFailureMessage(final.failure), exitCode: 74)
  }
  _ = try dependencies.stateStore.update(sessionID: sessionID) {
    $0.phase = .failed
    $0.cleanupVerified = false
    $0.failure = "cleanup_receipt_missing"
  }
  return .failure(
    "PowerVPN: SSH ended, but the cleanup receipt did not arrive. Reconnect is blocked.",
    exitCode: 74
  )
}

private func runUserProductUp(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments.count == 2 else {
    throw UserProductCommandError.invalidArguments("usage: powervpn up <target>")
  }
  let commandLock: UserProductSessionCommandLock
  do {
    commandLock = try dependencies.stateStore.acquireCommandLock()
  } catch UserProductSessionStoreError.busy {
    return .failure("PowerVPN: another session command is already running.", exitCode: 75)
  }
  defer { withExtendedLifetime(commandLock) {} }
  let target = try resolveUserProductTarget(arguments[1], dependencies: dependencies)
  guard
    let sshConfiguration = effectiveSSHConfiguration(
      target: target,
      dependencies: dependencies
    )
  else {
    return .failure(
      "PowerVPN: SSH target '\(target.key)' does not match targets.json or lacks ControlMaster configuration."
    )
  }

  if let existing = try dependencies.stateStore.load() {
    let check = checkMaster(existing, dependencies: dependencies)
    if check.exitCode == 0 {
      if existing.target == target.key {
        return .success(
          "PowerVPN: connected\nTarget: \(target.key)\nSession: already active\n"
        )
      }
      return .failure(
        "PowerVPN: already connected to \(existing.target). Run `powervpn down` first."
      )
    }
    if existing.terminal, existing.cleanupVerified == true {
      _ = try dependencies.stateStore.remove(sessionID: existing.sessionID)
    } else if existing.terminal {
      return .failure(
        "PowerVPN: the previous session did not prove cleanup. Run `powervpn doctor --json` before reconnecting.",
        exitCode: 74
      )
    } else if dependencies.mutationLeaseAvailable() {
      _ = try dependencies.stateStore.update(sessionID: existing.sessionID) {
        $0.phase = .failed
        $0.cleanupVerified = false
        $0.failure = "stale_session_cleanup_unverified"
      }
      return .failure(
        "PowerVPN: a stale session was detected, but cleanup cannot be proven. Run `powervpn doctor --json` before reconnecting.",
        exitCode: 74
      )
    } else {
      return .failure(
        "PowerVPN: the previous session is still starting or cleaning up. Run `powervpn status`."
      )
    }
  }

  let foreign = dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.checkMaster(
      target: target.key,
      controlPath: sshConfiguration.controlPath
    ),
    io: .captured
  )
  if foreign.exitCode == 0 {
    return .failure(
      "PowerVPN: an existing SSH ControlMaster for \(target.key) is not owned by PowerVPN. Close it before `powervpn up`."
    )
  }
  guard removeOwnedStaleControlSocket(sshConfiguration.controlPath) else {
    return .failure("PowerVPN: the configured SSH control socket is unsafe or cannot be recovered.")
  }

  let sessionID = UUID().uuidString.lowercased()
  let connecting = UserProductSessionState(
    sessionID: sessionID,
    target: target.key,
    controlPath: sshConfiguration.controlPath,
    phase: .connecting
  )
  try dependencies.stateStore.save(connecting)

  let launch = dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.startMaster(
      target: target.key,
      controlPath: sshConfiguration.controlPath,
      executablePath: dependencies.executablePath,
      sessionID: sessionID
    ),
    io: .discarded
  )
  guard launch.started, launch.exitCode == 0 else {
    if let final = try dependencies.stateStore.load(), final.sessionID == sessionID,
      final.terminal
    {
      return .failure(userProductFailureMessage(final.failure), exitCode: 69)
    }
    _ = try dependencies.stateStore.update(sessionID: sessionID) {
      $0.phase = .failed
      $0.failure = "ssh_master_start_failed"
      $0.cleanupVerified = dependencies.mutationLeaseAvailable()
    }
    return .failure(
      "PowerVPN: SSH master did not start. Check SSH keys and run `powervpn doctor --json`."
    )
  }

  let readiness = checkMaster(connecting, dependencies: dependencies)
  guard readiness.exitCode == 0 else {
    if let final = try dependencies.stateStore.load(), final.sessionID == sessionID,
      final.terminal
    {
      return .failure(userProductFailureMessage(final.failure), exitCode: 69)
    }
    return .failure(
      "PowerVPN: session startup has not reached READY. Run `powervpn status`."
    )
  }
  let ownerPID = userProductMasterPID(readiness.output)
  _ = try dependencies.stateStore.update(sessionID: sessionID) { state in
    if state.phase == .connecting {
      state.phase = .connected
      state.ownerPID = ownerPID
    }
  }
  return .success(
    "PowerVPN: connected\nTarget: \(target.key)\nSession: active\nSSH: ssh \(target.key)\n"
  )
}

private func runUserProductDown(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments.count == 1 else {
    throw UserProductCommandError.invalidArguments("usage: powervpn down")
  }
  let commandLock: UserProductSessionCommandLock
  do {
    commandLock = try dependencies.stateStore.acquireCommandLock()
  } catch UserProductSessionStoreError.busy {
    return .failure("PowerVPN: another session command is already running.", exitCode: 75)
  }
  defer { withExtendedLifetime(commandLock) {} }
  guard var state = try dependencies.stateStore.load() else {
    return .success("PowerVPN: disconnected\n")
  }
  if state.terminal {
    if state.cleanupVerified == true {
      _ = try dependencies.stateStore.remove(sessionID: state.sessionID)
      return .success("PowerVPN: disconnected\nCleanup: verified\n")
    }
    return .failure(
      "PowerVPN: previous session ended but cleanup was not verified. Run `powervpn doctor --json`.",
      exitCode: 74
    )
  }

  let check = checkMaster(state, dependencies: dependencies)
  if check.exitCode == 0 {
    _ = try dependencies.stateStore.update(sessionID: state.sessionID) {
      $0.phase = .disconnecting
    }
    let stop = dependencies.processRunner.run(
      executable: "/usr/bin/ssh",
      arguments: UserProductSSHArguments.stopMaster(
        target: state.target,
        controlPath: state.controlPath
      ),
      io: .captured
    )
    if !stop.started || stop.exitCode != 0 {
      return .failure(
        "PowerVPN: could not ask the persistent SSH session to stop. Run `powervpn status`."
      )
    }
  }

  for _ in 0..<dependencies.cleanupPollLimit {
    if let current = try dependencies.stateStore.load(), current.sessionID == state.sessionID {
      state = current
      if current.terminal {
        if current.phase == .disconnected, current.cleanupVerified == true {
          _ = try dependencies.stateStore.remove(sessionID: current.sessionID)
          return .success("PowerVPN: disconnected\nCleanup: verified\n")
        }
        return .failure(userProductFailureMessage(current.failure), exitCode: 74)
      }
    } else {
      return .failure(
        "PowerVPN: the session cleanup receipt disappeared. Reconnect is blocked.",
        exitCode: 74
      )
    }
    if dependencies.mutationLeaseAvailable(),
      checkMaster(state, dependencies: dependencies).exitCode != 0
    {
      _ = try dependencies.stateStore.update(sessionID: state.sessionID) {
        $0.phase = .failed
        $0.cleanupVerified = false
        $0.failure = "stale_session_cleanup_unverified"
      }
      return .failure(
        "PowerVPN: the session owner exited without a cleanup receipt. Reconnect is blocked until diagnostics confirm recovery.",
        exitCode: 74
      )
    }
    await dependencies.sleepMilliseconds(500)
  }
  return .failure(
    "PowerVPN: disconnect is still cleaning up. Run `powervpn status` before reconnecting.",
    exitCode: 74
  )
}

private func runUserProductStatus(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments == ["status"] || arguments == ["status", "--json"] else {
    throw UserProductCommandError.invalidArguments("usage: powervpn status [--json]")
  }
  let json = arguments.last == "--json"
  let configurationReady = (try? dependencies.loadConfiguration().productTargetsComplete) == true
  let system = dependencies.systemStatus()
  var warning: String?
  let report: UserProductStatusReport
  if let state = try dependencies.stateStore.load() {
    let check =
      state.terminal
      ? UserProductProcessResult(started: true, exitCode: 255, output: "")
      : checkMaster(state, dependencies: dependencies)
    if check.exitCode == 0 {
      let connectionState: UserProductConnectionState
      switch state.phase {
      case .connecting: connectionState = .connecting
      case .disconnecting: connectionState = .disconnecting
      case .connected, .disconnected, .failed: connectionState = .connected
      }
      report = UserProductStatusReport(
        state: connectionState,
        target: state.target,
        sessionActive: true,
        ownerPID: userProductMasterPID(check.output) ?? state.ownerPID,
        thuReady: configurationReady,
        warning: nil
      )
    } else if !dependencies.mutationLeaseAvailable() {
      report = UserProductStatusReport(
        state: state.phase == .disconnecting ? .disconnecting : .connecting,
        target: state.target,
        sessionActive: false,
        ownerPID: state.ownerPID,
        thuReady: configurationReady,
        warning: "Session owner is starting or cleanup is still running."
      )
    } else {
      if state.cleanupVerified != true {
        warning = "Previous session ended unexpectedly; cleanup is not verified."
      }
      if state.cleanupVerified == true {
        _ = try dependencies.stateStore.remove(sessionID: state.sessionID)
      } else if !state.terminal {
        _ = try dependencies.stateStore.update(sessionID: state.sessionID) {
          $0.phase = .failed
          $0.cleanupVerified = false
          $0.failure = "stale_session_cleanup_unverified"
        }
      }
      report = UserProductStatusReport(
        state: state.cleanupVerified == true ? .disconnected : .cleanupFailed,
        target: nil,
        sessionActive: false,
        ownerPID: nil,
        thuReady: configurationReady,
        warning: warning ?? historicalHelperWarning(system)
      )
    }
  } else {
    if !dependencies.mutationLeaseAvailable() {
      report = UserProductStatusReport(
        state: .disconnecting,
        target: nil,
        sessionActive: false,
        ownerPID: nil,
        thuReady: configurationReady,
        warning: "A foreground session is still cleaning up."
      )
      return try encodeUserProductStatus(report, json: json)
    }
    report = UserProductStatusReport(
      state: .disconnected,
      target: nil,
      sessionActive: false,
      ownerPID: nil,
      thuReady: configurationReady,
      warning: historicalHelperWarning(system)
    )
  }
  return try encodeUserProductStatus(report, json: json)
}

private func encodeUserProductStatus(
  _ report: UserProductStatusReport,
  json: Bool
) throws -> UserProductCommandResult {
  if json {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return .success(String(decoding: try encoder.encode(report), as: UTF8.self) + "\n")
  }
  var lines = ["PowerVPN: \(report.state.rawValue)"]
  if let target = report.target { lines.append("Target: \(target)") }
  if report.sessionActive { lines.append("Session: active") }
  lines.append("THU: \(report.thuReady ? "ready" : "configuration required")")
  if let warning = report.warning {
    lines.append("Warning: \(warning)")
    lines.append("Run `powervpn doctor --json` for details.")
  }
  return .success(lines.joined(separator: "\n") + "\n")
}

private func runUserProductDoctor(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) throws -> UserProductCommandResult {
  guard arguments == ["doctor"] || arguments == ["doctor", "--json"] else {
    throw UserProductCommandError.invalidArguments("usage: powervpn doctor [--json]")
  }
  let configurationSafe = (try? dependencies.loadConfiguration().productTargetsComplete) == true
  let credentialsSafe = protectedUserFileIsSafe(
    ("~/.config/powervpn/credentials.env" as NSString).expandingTildeInPath
  )
  let system = dependencies.systemStatus()
  let helperInstalled =
    system.appVersion != nil && system.appBuild != nil
    && protectedRootExecutableIsSafe(
      "/Library/PrivilegedHelperTools/com.leadsec.charon-xpc"
    )
  let logSafe = protectedRootLogIsSafe("/var/log/vsgvpn.log")
  let session = try dependencies.stateStore.load()
  let sessionCleanupSafe = session?.cleanupVerified != false
  let blocker: String?
  if !configurationSafe {
    blocker = "target_configuration_incomplete"
  } else if !credentialsSafe {
    blocker = "credential_file_unsafe"
  } else if !helperInstalled {
    blocker = "vendor_helper_missing"
  } else if !logSafe {
    blocker = "vendor_log_permissions_unsafe"
  } else if !sessionCleanupSafe {
    blocker = "previous_cleanup_unverified"
  } else {
    blocker = nil
  }
  let warning = historicalHelperWarning(system)
  let report = UserProductDoctorReport(
    ready: blocker == nil,
    targetConfigurationSafe: configurationSafe,
    credentialFileSafe: credentialsSafe,
    helperInstalled: helperInstalled,
    vendorLogSafe: logSafe,
    sessionCleanupSafe: sessionCleanupSafe,
    blocker: blocker,
    warning: warning
  )
  if arguments.last == "--json" {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return UserProductCommandResult(
      standardOutput: String(decoding: try encoder.encode(report), as: UTF8.self) + "\n",
      standardError: "",
      exitCode: report.ready ? 0 : 2
    )
  }
  var lines = ["PowerVPN doctor: \(report.ready ? "ready" : "blocked")"]
  if let blocker { lines.append("Blocker: \(blocker)") }
  if let warning { lines.append("Warning: \(warning)") }
  return UserProductCommandResult(
    standardOutput: lines.joined(separator: "\n") + "\n",
    standardError: "",
    exitCode: report.ready ? 0 : 2
  )
}

private func runInternalProductProxy(
  arguments: [String],
  sessionID: String?,
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments.count == 4,
    let port = UInt16(arguments[3]), port > 0
  else { throw UserProductCommandError.invalidArguments("internal command rejected") }
  let target = try resolveUserProductTarget(arguments[1], dependencies: dependencies)
  guard target.host == arguments[2], port == 22 else {
    return .failure("PowerVPN: SSH destination does not match the configured target.", exitCode: 70)
  }
  let result = try await dependencies.proxyRunner([
    "proxy", "ssh",
    "--resource-display-name", target.resource,
    "--ssh-target", target.key,
    target.host, "22", "--non-interactive",
  ])
  let stateBeforeCompletion = sessionID.flatMap { expectedID in
    guard let state = try? dependencies.stateStore.load(), state.sessionID == expectedID else {
      return nil as UserProductSessionState?
    }
    return state
  }
  let readySessionClosedWithCleanup =
    sessionID != nil
    && result.exitCode != 74
    && (stateBeforeCompletion?.phase == .connected
      || stateBeforeCompletion?.phase == .disconnecting)
  let proxyStreamClosedWithCleanup =
    sessionID != nil
    && result.exitCode != 74
    && result.standardError.trimmingCharacters(in: .whitespacesAndNewlines) == "child_failed"
  let normalSessionClose = readySessionClosedWithCleanup || proxyStreamClosedWithCleanup
  let failure =
    result.exitCode == 0 || normalSessionClose
    ? nil : userProductProxyFailure(result.standardError)
  if let sessionID {
    _ = try? dependencies.stateStore.update(sessionID: sessionID) { state in
      state.phase = result.exitCode == 0 || normalSessionClose ? .disconnected : .failed
      state.cleanupVerified = result.exitCode != 74
      state.failure = failure
    }
  }
  return UserProductCommandResult(
    standardOutput: result.standardOutput,
    standardError: failure.map { userProductFailureMessage($0) + "\n" } ?? "",
    exitCode: result.exitCode
  )
}

private func resolveUserProductTarget(
  _ key: String,
  dependencies: UserProductCommandDependencies
) throws -> UserProductTarget {
  guard ProductM2SSHTarget(rawValue: key) != nil else {
    throw UserProductCommandError.invalidArguments("invalid target: \(key)")
  }
  let configuration: PowerVPNTargetsConfiguration
  do {
    configuration = try dependencies.loadConfiguration()
  } catch let error as PowerVPNTargetsConfigurationError {
    throw UserProductCommandError.invalidArguments(error.token)
  }
  let configured: PowerVPNTargetConfiguration
  do {
    configured = try configuration.target(named: key)
  } catch let error as PowerVPNTargetsConfigurationError {
    throw UserProductCommandError.invalidArguments(error.token)
  }
  guard let resource = configured.resourceDisplayName else {
    throw UserProductCommandError.invalidArguments(
      "target '\(key)' is missing its resource mapping in targets.json"
    )
  }
  return UserProductTarget(
    key: key,
    host: configured.host,
    user: configured.user,
    resource: resource
  )
}

private func effectiveSSHConfiguration(
  target: UserProductTarget,
  dependencies: UserProductCommandDependencies
) -> UserProductSSHEffectiveConfiguration? {
  let result = dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.configuration(target: target.key),
    io: .captured
  )
  guard result.started, result.exitCode == 0,
    let parsed = UserProductSSHEffectiveConfiguration.parse(result.output),
    parsed.hostname == target.host,
    parsed.user == target.user,
    parsed.port == 22,
    parsed.controlMaster == "auto" || parsed.controlMaster == "yes",
    parsed.controlPath.hasPrefix(
      FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".ssh", isDirectory: true).path + "/"
    )
  else { return nil }
  return parsed
}

private func checkMaster(
  _ state: UserProductSessionState,
  dependencies: UserProductCommandDependencies
) -> UserProductProcessResult {
  dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.checkMaster(
      target: state.target,
      controlPath: state.controlPath
    ),
    io: .captured
  )
}

private func historicalHelperWarning(_ status: PowerVPNStatus) -> String? {
  guard !status.helper.isRunning,
    status.helper.successiveCrashes.map({ $0 > 0 }) == true,
    status.helper.lastTerminatingSignal != nil
  else { return nil }
  return "vendor helper crashed during a previous cleanup; the current session is disconnected."
}

private func protectedUserFileIsSafe(_ path: String) -> Bool {
  var metadata = stat()
  return lstat(path, &metadata) == 0
    && metadata.st_uid == getuid()
    && metadata.st_mode & S_IFMT == S_IFREG
    && metadata.st_mode & 0o777 == 0o600
    && metadata.st_size > 0
}

private func protectedRootLogIsSafe(_ path: String) -> Bool {
  var metadata = stat()
  guard lstat(path, &metadata) == 0 else { return errno == ENOENT }
  return metadata.st_uid == 0
    && metadata.st_gid == 0
    && metadata.st_mode & S_IFMT == S_IFREG
    && metadata.st_mode & 0o777 == 0o600
    && metadata.st_size <= 0x1E00_000
}

private func protectedRootExecutableIsSafe(_ path: String) -> Bool {
  var metadata = stat()
  return lstat(path, &metadata) == 0
    && metadata.st_uid == 0
    && metadata.st_mode & S_IFMT == S_IFREG
    && metadata.st_mode & S_IXUSR != 0
    && metadata.st_mode & (S_IWGRP | S_IWOTH) == 0
}

private func userProductProxyFailure(_ raw: String) -> String {
  if raw.contains("integration_info_missing") { return "portal_catalog_incomplete" }
  if raw.contains("preflight_rejected") { return "local_safety_check_failed" }
  if raw.contains("resource_not_found") { return "target_resource_unavailable" }
  if raw.contains("cleanup_unproven") { return "cleanup_unproven" }
  if raw.contains("runtime_unavailable") { return "runtime_unavailable" }
  return "connection_failed"
}

private func userProductFailureMessage(_ failure: String?) -> String {
  switch failure {
  case "portal_catalog_incomplete":
    return
      "PowerVPN: THU Portal returned an incomplete resource list after one bounded retry. Try again shortly."
  case "local_safety_check_failed":
    return "PowerVPN: a local safety check blocked the connection. Run `powervpn doctor --json`."
  case "target_resource_unavailable":
    return "PowerVPN: the configured THU resource is not currently available."
  case "cleanup_unproven":
    return
      "PowerVPN: the session ended, but network cleanup could not be verified. Do not reconnect until `powervpn doctor --json` is clean."
  case "runtime_unavailable":
    return "PowerVPN: Portal credentials or target configuration are unavailable."
  case "ssh_master_start_failed":
    return "PowerVPN: the persistent SSH owner could not start."
  case "stale_session_cleanup_unverified":
    return "PowerVPN: a stale session was detected and quarantined because cleanup is unverified."
  case "cleanup_receipt_missing":
    return "PowerVPN: cleanup could not be verified because the session receipt is missing."
  default:
    return "PowerVPN: connection failed. Run `powervpn doctor --json` for details."
  }
}

private func waitForSessionReceipt(
  sessionID: String,
  dependencies: UserProductCommandDependencies
) async -> UserProductSessionState? {
  for _ in 0..<dependencies.cleanupPollLimit {
    guard let state = try? dependencies.stateStore.load(), state.sessionID == sessionID else {
      return nil
    }
    if state.terminal { return state }
    await dependencies.sleepMilliseconds(500)
  }
  return nil
}
