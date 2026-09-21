import Foundation
import PowerVPNPortal
import PowerVPNProduct

private enum UserProductRecoveryOperation: String, Encodable {
  case inspect
  case clear
}

private struct UserProductRecoveryCommandReport: Encodable {
  let schemaVersion = 1
  let operation: UserProductRecoveryOperation
  let outcome: String
  let target: String?
  let originalCleanupVerified: Bool?
  let originalFailure: String?
  let originalCleanupReceipt: UserProductOriginalCleanupReceipt?
  let recoveryReceipt: UserProductRecoveryReceipt?
  let measurement: ProductCleanupRecoveryReport?
  let quarantineCleared: Bool
  let requiresHumanAction: Bool
  let nextAction: String?
  let containsSecrets = false
  let snapshotSerialized = false
}

func runUserProductRecovery(
  arguments: [String],
  dependencies: UserProductCommandDependencies
) async throws -> UserProductCommandResult {
  guard arguments.count == 3, arguments[0] == "recovery",
    let operation = UserProductRecoveryOperation(rawValue: arguments[1]),
    arguments[2] == "--json"
  else {
    throw UserProductCommandError.invalidArguments(
      "usage: powervpn recovery <inspect|clear> --json"
    )
  }

  let commandLock: UserProductSessionCommandLock
  do {
    commandLock = try dependencies.stateStore.acquireCommandLock()
  } catch UserProductSessionStoreError.busy {
    return try recoveryResult(
      operation: operation,
      outcome: "command_busy",
      requiresHumanAction: true,
      exitCode: 75
    )
  }
  defer { withExtendedLifetime(commandLock) {} }

  guard let state = try dependencies.stateStore.load() else {
    return try recoveryResult(
      operation: operation,
      outcome: "not_required",
      quarantineCleared: true,
      requiresHumanAction: false,
      exitCode: 0
    )
  }
  guard state.terminal, state.cleanupVerified != true else {
    return try recoveryResult(
      operation: operation,
      outcome: state.cleanupVerified == true ? "not_required" : "session_active",
      state: state,
      quarantineCleared: state.cleanupVerified == true,
      requiresHumanAction: state.cleanupVerified != true,
      exitCode: state.cleanupVerified == true ? 0 : 74
    )
  }
  if let receipt = state.recoveryReceipt, receipt.permitsReconnect {
    return try recoveryResult(
      operation: operation,
      outcome: "already_recovered",
      state: state,
      recoveryReceipt: receipt,
      quarantineCleared: true,
      requiresHumanAction: false,
      exitCode: 0
    )
  }

  let master = dependencies.processRunner.run(
    executable: "/usr/bin/ssh",
    arguments: UserProductSSHArguments.checkMaster(
      target: state.target,
      controlPath: state.controlPath
    ),
    io: .captured
  )
  guard master.started, master.exitCode != 0 else {
    return try recoveryResult(
      operation: operation,
      outcome: master.started ? "session_active" : "master_check_failed",
      state: state,
      requiresHumanAction: true,
      exitCode: 74
    )
  }

  let configuration: PowerVPNTargetsConfiguration
  let target: ProductM2SSHTarget
  let resource: String
  do {
    configuration = try dependencies.loadConfiguration()
    let resolved = try ProductM2SSHTarget(key: state.target, configuration: configuration)
    guard let displayName = try configuration.target(named: state.target).resourceDisplayName else {
      return try recoveryResult(
        operation: operation,
        outcome: "target_configuration_incomplete",
        state: state,
        requiresHumanAction: true,
        exitCode: 74
      )
    }
    target = resolved
    resource = displayName
  } catch {
    return try recoveryResult(
      operation: operation,
      outcome: "target_configuration_rejected",
      state: state,
      requiresHumanAction: true,
      exitCode: 74
    )
  }

  let request = ProductCleanupRecoveryRequest(
    resourceDisplayName: resource,
    sshTarget: target
  )
  let measurement: ProductCleanupRecoveryReport
  let committedReceipt = UserProductRecoveryReceiptBox()
  if operation == .clear {
    measurement = await runRecoverySignalTask(
      signalMonitorFactory: dependencies.signalMonitorFactory
    ) {
      await dependencies.recoveryRunner(request, configuration) { report in
        guard
          let receipt = persistRecovery(
            report,
            originalState: state,
            stateStore: dependencies.stateStore
          )
        else { return false }
        committedReceipt.store(receipt)
        return true
      }
    }
  } else {
    measurement = await runRecoverySignalTask(
      signalMonitorFactory: dependencies.signalMonitorFactory
    ) {
      await dependencies.recoveryRunner(request, configuration) { _ in true }
    }
  }

  if measurement.failure == .cancelled {
    return try recoveryResult(
      operation: operation,
      outcome: "cancelled",
      state: state,
      measurement: measurement,
      quarantineCleared: false,
      requiresHumanAction: true,
      exitCode: 130
    )
  }

  if operation == .inspect {
    return try recoveryResult(
      operation: operation,
      outcome: measurement.permitsReconnect ? "measurement_passed" : "measurement_rejected",
      state: state,
      measurement: measurement,
      quarantineCleared: false,
      requiresHumanAction: true,
      nextAction: measurement.permitsReconnect
        ? "powervpn recovery clear --json" : nil,
      exitCode: measurement.permitsReconnect ? 0 : 74
    )
  }

  let receipt =
    committedReceipt.value
    ?? UserProductRecoveryReceipt(
      report: measurement,
      originalSessionID: state.sessionID,
      target: state.target,
      originalFailure: state.failure,
      noActiveMaster: true
    )
  let cleared = operation == .clear && measurement.permitsReconnect
  return try recoveryResult(
    operation: operation,
    outcome: measurement.outcome.rawValue,
    state: state,
    recoveryReceipt: receipt,
    measurement: measurement,
    quarantineCleared: cleared,
    requiresHumanAction: !measurement.permitsReconnect,
    exitCode: measurement.permitsReconnect ? 0 : 74
  )
}

private func runRecoverySignalTask(
  signalMonitorFactory: CLISignalMonitorFactory,
  operation: @escaping @Sendable () async -> ProductCleanupRecoveryReport
) async -> ProductCleanupRecoveryReport {
  let cancellation = CLITaskCancellation<ProductCleanupRecoveryReport>()
  let monitor = signalMonitorFactory()
  monitor.start { cancellation.request() }
  defer {
    cancellation.clear()
    monitor.stop()
  }
  let gate = CLITaskStartGate()
  let task = Task {
    await gate.wait()
    return await operation()
  }
  cancellation.install(task)
  await gate.open()
  return await task.value
}

private func persistRecovery(
  _ report: ProductCleanupRecoveryReport,
  originalState: UserProductSessionState,
  stateStore: UserProductSessionStateStore
) -> UserProductRecoveryReceipt? {
  guard report.permitsReconnect, !Task.isCancelled else { return nil }
  let receipt = UserProductRecoveryReceipt(
    report: report,
    originalSessionID: originalState.sessionID,
    target: originalState.target,
    originalFailure: originalState.failure,
    noActiveMaster: true
  )
  let archive = UserProductRecoveryArchive(
    schemaVersion: 1,
    originalSessionID: originalState.sessionID,
    target: originalState.target,
    originalCleanupVerified: originalState.cleanupVerified == true,
    originalFailure: originalState.failure,
    originalCleanupReceipt: originalState.originalCleanupReceipt,
    recoveryReceipt: receipt,
    containsSecrets: false
  )
  guard receipt.valid, archive.valid else { return nil }
  do {
    try stateStore.saveRecoveryArchive(archive)
    guard !Task.isCancelled else {
      _ = try? stateStore.removeRecoveryArchive(expected: archive)
      return nil
    }
    let committed = try stateStore.compareAndUpdate(expected: originalState) { state in
      state.schemaVersion = 2
      state.recoveryReceipt = receipt
    }
    guard committed else {
      _ = try? stateStore.removeRecoveryArchive(expected: archive)
      return nil
    }
    return receipt
  } catch {
    if let current = try? stateStore.load(), current.recoveryReceipt == receipt {
      return receipt
    }
    _ = try? stateStore.removeRecoveryArchive(expected: archive)
    return nil
  }
}

private final class UserProductRecoveryReceiptBox: @unchecked Sendable {
  private let lock = NSLock()
  private var receipt: UserProductRecoveryReceipt?

  func store(_ value: UserProductRecoveryReceipt) {
    lock.withLock { receipt = value }
  }

  var value: UserProductRecoveryReceipt? { lock.withLock { receipt } }
}

private func recoveryResult(
  operation: UserProductRecoveryOperation,
  outcome: String,
  state: UserProductSessionState? = nil,
  recoveryReceipt: UserProductRecoveryReceipt? = nil,
  measurement: ProductCleanupRecoveryReport? = nil,
  quarantineCleared: Bool = false,
  requiresHumanAction: Bool,
  nextAction: String? = nil,
  exitCode: Int32
) throws -> UserProductCommandResult {
  let report = UserProductRecoveryCommandReport(
    operation: operation,
    outcome: outcome,
    target: state?.target,
    originalCleanupVerified: state?.cleanupVerified,
    originalFailure: state?.failure,
    originalCleanupReceipt: state?.originalCleanupReceipt,
    recoveryReceipt: recoveryReceipt,
    measurement: measurement,
    quarantineCleared: quarantineCleared,
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
