import Foundation
import PowerVPNCore
import PowerVPNPortal

/// Stable failure tokens for the native backend. They end up in the
/// `powervpn run:` / `next:` lines, so keep them short and actionable.
package enum NativeTunnelFailure: String, Error, Equatable, Sendable {
  case helperUnavailable = "native_helper_unavailable"
  case charonUnavailable = "native_charon_unavailable"
  case targetInvalid = "native_target_invalid"
  case portalRejected = "native_portal_rejected"
  case portalUnavailable = "native_portal_unavailable"
  case portalConfigurationRejected = "native_portal_configuration_rejected"
  case cleanupUnproven = "native_cleanup_unproven"
  case resourceUnavailable = "native_resource_unavailable"
  case ikeFailed = "native_ike_failed"
  case childFailed = "native_child_failed"
  /// charon could not create or see the tunnel's virtual IP on the Mac: a local
  /// fault, not a gateway refusal.
  case localVirtualIPFailed = "native_local_vip_failed"
  case routeRejected = "native_route_rejected"
  case busy = "native_session_busy"
  case cancelled = "native_cancelled"

  package var next: String {
    switch self {
    case .helperUnavailable, .charonUnavailable:
      "install or restart the native backend: \(NativeBundledPayload.installCommand)"
    case .targetInvalid: "fix the target in ~/.config/powervpn/targets.json"
    case .portalRejected: "check ~/.config/powervpn/credentials.env and the Portal account"
    case .portalConfigurationRejected: "check the Portal origin and TLS trust in targets.json"
    case .cleanupUnproven: "powervpn down (inspect local recovery and Portal cleanup separately)"
    case .resourceUnavailable:
      "make `resource` in targets.json match the Portal resource name exactly"
    case .localVirtualIPFailed:
      "sudo launchctl kickstart -k system/\(NativeHelperPaths.label), then retry (evidence: powervpn native log)"
    case .portalUnavailable, .ikeFailed, .childFailed, .routeRejected, .busy, .cancelled:
      "retry the same command (if it repeats: powervpn native log)"
    }
  }

  package static func portalFailure(_ report: PortalLoginReport) -> Self {
    if report.status == .cancelled || report.transportFailure?.category == .cancelled {
      return .cancelled
    }
    switch report.transportFailure?.category {
    case .httpAuthenticationRejected: return .portalRejected
    case .trustRejected, .redirectRejected, .invalidRequest, .setupFailed:
      return .portalConfigurationRejected
    default: break
    }
    switch report.status {
    case .credentialInputRejected, .loginRejected, .challengeRequired: return .portalRejected
    case .configurationRejected, .tlsRejected, .redirectRejected:
      return .portalConfigurationRejected
    default: return .portalUnavailable
    }
  }
}

package struct NativeTunnelCleanupReport: Codable, Equatable, Sendable {
  package let routeRemoved: Bool
  package let sessionRemoved: Bool
  package let portalStatus: String
  package let portalFailureClass: String?
  package var portalVerification: PortalLogoutVerificationEvidence? = nil
  package var localCleanupVerified: Bool { routeRemoved && sessionRemoved }
  package var portalCleanupVerified: Bool {
    guard portalStatus == "accepted" else { return false }
    if let portalVerification { return portalVerification.after.confirmsInvalidation }
    return portalFailureClass == "completed_remote_exchange"
  }
  package var cleanupVerified: Bool { localCleanupVerified && portalCleanupVerified }
  package var portalSessionStillValid: Bool { portalVerification?.after.state == .valid }
  package var valid: Bool {
    PortalLeaseLogoutStatus(rawValue: portalStatus) != nil
      && (portalFailureClass == nil
        || portalFailureClass.flatMap(PortalLeaseLogoutFailureClass.init(rawValue:)) != nil)
  }
}

package struct NativeTunnelOpenFailure: Error, Equatable, Sendable {
  package let failure: NativeTunnelFailure
  package var helperMutationRequested = false
  package var serverContactRequested = false
  package var cleanupVerified = true
  package var cleanupReport: NativeTunnelCleanupReport? = nil
  /// Why the step failed, when charon or its log said so.
  package var detail: NativeFailureDetail? = nil

  package init(
    failure: NativeTunnelFailure, helperMutationRequested: Bool = false,
    serverContactRequested: Bool = false, cleanupVerified: Bool = true,
    cleanupReport: NativeTunnelCleanupReport? = nil, detail: NativeFailureDetail? = nil
  ) {
    self.detail = detail
    self.failure = failure
    self.helperMutationRequested = helperMutationRequested
    self.serverContactRequested = serverContactRequested
    self.cleanupVerified = cleanupVerified
    self.cleanupReport = cleanupReport
  }

  package init(portal report: PortalLoginReport) {
    failure = .portalFailure(report)
    serverContactRequested = report.operations.loginRequested
    let explicitlyRejected =
      !report.operations.loginAccepted
      && (report.status == .loginRejected || report.status == .challengeRequired
        || report.transportFailure?.category == .httpAuthenticationRejected)
    // A request can reach the server even when its response never reaches us.
    // `loginAccepted` is an observation, not evidence of server-side absence.
    let portalClosed =
      !report.operations.loginRequested || explicitlyRejected
      || report.operations.logoutAccepted
    let material = report.ownedMaterial
    cleanupVerified =
      portalClosed && material.credentialsErased && material.requestBodiesErased
      && material.responseBodiesErased && material.sessionMaterialErased
  }
}

/// What `open` does after a failed attempt. Pure, so the retry and restart
/// rules are tested without a helper.
package enum NativeOpenNextStep: Equatable, Sendable {
  case stop
  /// Fresh Portal login after a short delay (the catalog intermittently lacks
  /// the resource).
  case retryAfterDelay
  /// Ask the helper to restart charon, then one fresh attempt.
  case restartCharonThenRetry

  package static func after(
    failure: NativeTunnelFailure, attempt: Int, attempts: Int, charonRestarted: Bool,
    cleanupVerified: Bool, cancelled: Bool, helperCanRestart: Bool
  ) -> Self {
    // An unverified cleanup must reach the recovery path untouched, and a
    // restart would also destroy the evidence it needs.
    guard cleanupVerified, !cancelled else { return .stop }
    switch failure {
    case .localVirtualIPFailed:
      return !charonRestarted && helperCanRestart ? .restartCharonThenRetry : .stop
    case .resourceUnavailable:
      return attempt < attempts ? .retryAfterDelay : .stop
    default:
      return .stop
    }
  }
}

/// Per-attempt phase outcomes and timings, one sanitized line each, in the
/// user's own 0600 state directory. Only tokens and numbers are written, never
/// Portal or credential material.
package struct NativeAttemptLog: Sendable {
  let log: NativeRotatingLog?
  let attemptID: String

  package static var standardPath: String {
    NSHomeDirectory() + "/.local/state/powervpn/native-attempts.log"
  }

  package static func standard() -> NativeRotatingLog {
    NativeRotatingLog(path: standardPath, maximumBytes: 262_144, keep: 2)
  }

  init(_ log: NativeRotatingLog?) {
    self.log = log
    attemptID = String(UUID().uuidString.prefix(8)).lowercased()
  }

  /// One line from a process that is not opening a tunnel (`powervpn run`).
  package static func note(_ message: String, log: NativeRotatingLog? = standard()) {
    NativeAttemptLog(log).record(message)
  }

  func record(_ message: String) {
    let stamp = ISO8601DateFormatter().string(from: Date())
    log?.append("\(stamp) \(attemptID) " + NativeLogSanitizer.sanitize(message))
  }
}

/// Everything one native session owns, so shutdown can remove exactly that.
package final class NativeTunnel: @unchecked Sendable {
  package static let namePrefix = "powervpn-"

  package let targetIPv4: UInt32
  private let targetHost: String
  private let name: String
  private let lease: AuthenticatedPortalLease
  private let vici: String
  private let helper: String
  /// What the running helper reported in `status` before this attempt.
  private let helperCapabilities: Set<String>
  /// The open attempt's log, so a later loss line carries the same id.
  private let trail: NativeAttemptLog
  private let openedAt = ContinuousClock.now
  private let lock = NSLock()
  private var shutdownTask: Task<NativeTunnelCleanupReport, Never>?
  private var mutationRequested = false

  init(
    targetIPv4: UInt32, targetHost: String, name: String, lease: AuthenticatedPortalLease,
    vici: String, helper: String, helperCapabilities: Set<String> = [],
    trail: NativeAttemptLog = NativeAttemptLog(nil)
  ) {
    self.targetIPv4 = targetIPv4
    self.targetHost = targetHost
    self.name = name
    self.lease = lease
    self.vici = vici
    self.helper = helper
    self.helperCapabilities = helperCapabilities
    self.trail = trail
  }

  /// True when the root helper and charon are both up.
  package static func backendAvailable(
    helper: String = NativeHelperPaths.control
  ) -> NativeTunnelFailure? {
    probeBackend(helper: helper).failure
  }

  /// One `status` round trip: whether the backend is up, and the optional
  /// features the helper understands (none on a helper that predates them).
  static func probeBackend(helper: String) -> (
    failure: NativeTunnelFailure?, capabilities: Set<String>
  ) {
    guard let status = try? NativeHelperClient.send(.init(op: .status), socketPath: helper),
      status.ok
    else { return (.helperUnavailable, []) }
    return (status.charonRunning == true ? nil : .charonUnavailable, Set(status.capabilities ?? []))
  }

  package static func open(
    configuration: PowerVPNTargetsConfiguration,
    targetKey: String,
    vici: String = NativeHelperPaths.vici,
    helper: String = NativeHelperPaths.control,
    attemptLog: NativeRotatingLog? = NativeAttemptLog.standard()
  ) async -> Result<NativeTunnel, NativeTunnelOpenFailure> {
    let trail = NativeAttemptLog(attemptLog)
    let backend = await onBlockingThread { probeBackend(helper: helper) }
    if let failure = backend.failure {
      trail.record("open target=\(targetKey) backend=\(failure.rawValue)")
      return .failure(.init(failure: failure))
    }
    guard let target = try? configuration.target(named: targetKey),
      target.resourceDisplayName != nil
    else { return .failure(.init(failure: .targetInvalid)) }
    let name = namePrefix + targetKey + "-" + UUID().uuidString.prefix(8).lowercased()

    // Cleanup of an earlier owner belongs to explicit, leased recovery. A
    // standalone proxy must not silently erase that owner's cleanup evidence.
    let empty = await onBlockingThread { localStateIsEmpty(vici: vici, helper: helper) }
    guard empty else {
      trail.record("open target=\(targetKey) leftovers=present")
      return .failure(.init(failure: .cleanupUnproven, cleanupVerified: false))
    }
    if Task.isCancelled { return .failure(.init(failure: .cancelled)) }

    var attempt = 1
    var charonRestarted = false
    var restartNote: String?
    while true {
      // The Portal resource catalog intermittently comes back without the
      // selected resource; a fresh login usually returns it.
      let lease: AuthenticatedPortalLease
      switch await PortalLoginRuntime.acquire(configuration: configuration) {
      case .acquired(let acquired): lease = acquired
      case .rejected(let report):
        trail.record("attempt=\(attempt) portal=rejected")
        return .failure(.init(portal: report))
      }
      let tunnel = NativeTunnel(
        targetIPv4: target.ipv4, targetHost: target.host, name: name, lease: lease,
        vici: vici, helper: helper, helperCapabilities: backend.capabilities, trail: trail)
      let current = attempt
      let outcome = await onBlockingThread {
        tunnel.establish(target: target, trail: trail, attempt: current)
      }
      if outcome == nil, !Task.isCancelled {
        trail.record("attempt=\(attempt) established")
        return .success(tunnel)
      }
      let cleanup = await tunnel.shutdownReport()
      let failure: NativeTunnelFailure =
        Task.isCancelled ? .cancelled : (outcome?.failure ?? .cancelled)
      var detail = outcome?.detail
      if let restartNote { detail?.selfHeal = restartNote }
      trail.record(
        "attempt=\(attempt) failed=\(failure.rawValue) cleanup=\(cleanup.cleanupVerified)"
          + (detail.map { " " + $0.summary } ?? ""))
      let canRestart = backend.capabilities.contains(NativeHelperResponse.restartCharonCapability)
      let step = NativeOpenNextStep.after(
        failure: failure, attempt: attempt, attempts: portalAttempts,
        charonRestarted: charonRestarted, cleanupVerified: cleanup.cleanupVerified,
        cancelled: Task.isCancelled, helperCanRestart: canRestart)
      switch step {
      case .stop:
        if failure == .localVirtualIPFailed, !charonRestarted {
          detail?.selfHeal = canRestart ? "not_attempted" : "helper_without_restart"
        }
        return .failure(
          .init(
            failure: failure, helperMutationRequested: tunnel.mutationRequested,
            serverContactRequested: true, cleanupVerified: cleanup.cleanupVerified,
            cleanupReport: cleanup.cleanupVerified ? nil : cleanup, detail: detail))
      case .retryAfterDelay:
        try? await Task.sleep(for: .seconds(2))
        if Task.isCancelled {
          return .failure(.init(failure: .cancelled, serverContactRequested: true))
        }
        attempt += 1
      case .restartCharonThenRetry:
        let reply = await onBlockingThread {
          try? NativeHelperClient.send(
            .init(op: .restartCharon), socketPath: helper, timeoutSeconds: 30)
        }
        charonRestarted = true
        if reply?.ok == true {
          restartNote = "restarted_retry_failed"
          trail.record("attempt=\(attempt) charon restarted by helper; retrying once")
          try? await Task.sleep(for: .seconds(1))
        } else {
          let why = (reply?.error ?? "helper_unreachable")
            .replacingOccurrences(of: "restart_refused_", with: "")
          trail.record("attempt=\(attempt) charon restart refused: \(why)")
          detail?.selfHeal = "refused:" + why
          return .failure(
            .init(
              failure: failure, helperMutationRequested: tunnel.mutationRequested,
              serverContactRequested: true, cleanupVerified: true, detail: detail))
        }
        if Task.isCancelled {
          return .failure(.init(failure: .cancelled, serverContactRequested: true))
        }
      }
    }
  }

  private static let portalAttempts = 3

  package struct EstablishFailure: Equatable, Sendable {
    package let failure: NativeTunnelFailure
    package let detail: NativeFailureDetail?
  }

  private static func milliseconds(since start: ContinuousClock.Instant) -> Int {
    let parts = start.duration(to: .now).components
    return Int(parts.seconds * 1_000 + parts.attoseconds / 1_000_000_000_000_000)
  }

  /// charon's `errmsg` plus the helper's captured charon log lines for this
  /// attempt, classified on positive evidence only. The broker forces
  /// `loglevel=-1` on every initiate, so the log lines are the only source of
  /// the distinguishing detail; a helper without `log-tail` degrades to
  /// `unclassified` with the errmsg and the timing.
  private func analyze(
    phase: NativeFailurePhase, error: Error?, attemptStart: Date, startedAt: ContinuousClock.Instant
  ) -> NativeFailureDetail {
    var message: String?
    if case VICISessionError.commandFailed(_, let text)? = error { message = text }
    let elapsed = Self.milliseconds(since: startedAt)
    func classify(_ lines: [String]) -> NativeFailureDetail {
      NativeFailureClassifier.classify(
        phase: phase, charonMessage: message, logLines: lines, session: name,
        elapsedMilliseconds: elapsed)
    }
    guard helperCapabilities.contains(NativeHelperResponse.logTailCapability) else {
      return classify([])
    }
    var detail = classify([])
    // charon logs before it answers VICI, but the helper reads its pipe
    // asynchronously: look twice, briefly.
    for delay: useconds_t in [150_000, 400_000] {
      usleep(delay)
      if let reply = try? NativeHelperClient.send(
        .init(op: .logTail, lines: 120, sinceEpoch: attemptStart.timeIntervalSince1970 - 1),
        socketPath: helper, timeoutSeconds: 10, replyLimit: 131_072),
        reply.ok
      {
        detail = classify(reply.logLines ?? [])
      }
      if detail.cause != .unclassified { break }
    }
    return detail
  }

  private func establish(
    target: PowerVPNTargetConfiguration, trail: NativeAttemptLog, attempt: Int
  ) -> EstablishFailure? {
    let attemptStart = Date()
    guard let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 25_000) else {
      trail.record("attempt=\(attempt) vici=unavailable")
      return .init(failure: .charonUnavailable, detail: nil)
    }
    defer { session.close() }
    var clock = ContinuousClock.now
    func phase(_ label: String, _ outcome: String) {
      trail.record(
        "attempt=\(attempt) phase=\(label) outcome=\(outcome) ms=\(Self.milliseconds(since: clock))"
      )
      clock = .now
    }
    do {
      try NativeTrialPortalBridge.withRequests(
        snapshot: lease.snapshot, target: target, name: name, includePrivateRule: true
      ) { shared, connection in
        // A timeout after sending a request can still have mutated charon.
        mutationRequested = true
        _ = try session.request(command: "load-shared", message: shared)
        _ = try session.request(command: "load-conn", message: connection)
      }
      phase("load", "ok")
    } catch is NativeTrialPortalBridge.Failure {
      phase("load", "resource_unavailable")
      return .init(failure: .resourceUnavailable, detail: nil)
    } catch is NativeTrialMaterial.Failure {
      phase("load", "resource_unavailable")
      return .init(failure: .resourceUnavailable, detail: nil)
    } catch {
      phase("load", "failed")
      let started = clock
      return .init(
        failure: .ikeFailed,
        detail: analyze(phase: .ike, error: error, attemptStart: attemptStart, startedAt: started))
    }
    let ikeStart = clock
    do {
      _ = try session.streamedRequest(
        command: "initiate", event: "control-log",
        message: VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("timeout", "15000"), .keyValue("loglevel", "-1"),
        ]))
    } catch {
      phase("ike", "failed")
      return .init(
        failure: .ikeFailed,
        detail: analyze(phase: .ike, error: error, attemptStart: attemptStart, startedAt: ikeStart))
    }
    guard let ike = summary(session), ike.state == "ESTABLISHED" else {
      phase("ike", "not_established")
      return .init(
        failure: .ikeFailed,
        detail: analyze(phase: .ike, error: nil, attemptStart: attemptStart, startedAt: ikeStart))
    }
    phase("ike", "established")
    let childStart = clock
    var childError: Error?
    do {
      _ = try session.streamedRequest(
        command: "initiate", event: "control-log",
        message: VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("child", NativeTrialMaterial.childName),
          .keyValue("timeout", "15000"), .keyValue("loglevel", "-1"),
        ]))
    } catch { childError = error }
    if childError != nil || summary(session)?.hasInstalledChild != true {
      phase("child", "failed")
      let detail = analyze(
        phase: .child, error: childError, attemptStart: attemptStart, startedAt: childStart)
      return .init(
        failure: detail.cause == .localVirtualIP ? .localVirtualIPFailed : .childFailed,
        detail: detail)
    }
    phase("child", "installed")
    guard
      let routed = try? NativeHelperClient.send(
        .init(op: .routeAdd, ike: name, host: targetHost), socketPath: helper),
      routed.ok
    else {
      phase("route", "rejected")
      return .init(failure: .routeRejected, detail: nil)
    }
    phase("route", "added")
    return nil
  }

  private func summary(_ session: VICISession) -> NativeIKESummary? {
    guard
      let result = try? session.streamedRequest(
        command: "list-sas", event: "list-sa",
        message: VICIMessage(elements: [.keyValue("ike", name)]))
    else { return nil }
    return NativeIKESummary.parse(result.events).first { $0.name == name }
  }

  /// One probe of this session's IKE SAs (see `NativeTunnelLiveness`).
  package func liveness() async -> NativeTunnelLiveness {
    await onBlockingThread { Self.liveness(vici: self.vici) { $0 == self.name } }
  }

  /// The owner's watchdog confirmed the loss and is about to end the session.
  package func recordLost(consecutiveAbsent: Int) {
    let uptime = openedAt.duration(to: .now).components.seconds
    trail.record(
      "tunnel_lost reason=ike_sa_absent probes=\(consecutiveAbsent) uptime_s=\(uptime); closing the session"
    )
  }

  /// Removes the route, the SA, the loaded connection and the Portal session.
  /// Returns true only when each of them is verified gone.
  package func shutdown() async -> Bool {
    await shutdownReport().cleanupVerified
  }

  package func shutdownReport() async -> NativeTunnelCleanupReport {
    let task = lock.withLock { () -> Task<NativeTunnelCleanupReport, Never> in
      if let shutdownTask { return shutdownTask }
      let task = Task.detached { await self.performShutdown() }
      shutdownTask = task
      return task
    }
    return await task.value
  }

  private func performShutdown() async -> NativeTunnelCleanupReport {
    let local = await onBlockingThread { () -> (Bool, Bool) in
      if !self.mutationRequested { return (true, true) }
      let routeGone =
        (try? NativeHelperClient.send(
          .init(op: .routeDelete, host: self.targetHost), socketPath: self.helper))?.ok == true
      let saGone = removeSession(name: self.name, vici: self.vici)
      return (routeGone, saGone)
    }
    let logout = await lease.logoutAndErase(verifyInvalidation: true)
    return NativeTunnelCleanupReport(
      routeRemoved: local.0, sessionRemoved: local.1,
      portalStatus: logout.status.rawValue, portalFailureClass: logout.failureClass?.rawValue,
      portalVerification: logout.verification)
  }
}

extension NativeTunnel {
  /// Removes what a crashed or unverified earlier session may have left: our
  /// host routes for the configured targets and every `powervpn-` SA and
  /// connection/credential. This proves LOCAL cleanup only: a crashed owner's
  /// memory-only Portal lease cannot be recovered. Caller must hold the mutation
  /// lease and retain the original Portal cleanup uncertainty in session state.
  package static func recoverStale(
    configuration _: PowerVPNTargetsConfiguration,
    vici: String = NativeHelperPaths.vici,
    helper: String = NativeHelperPaths.control
  ) async -> Bool {
    return await onBlockingThread {
      guard let status = try? NativeHelperClient.send(.init(op: .status), socketPath: helper),
        status.ok, let hosts = status.routes,
        let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 5_000)
      else { return false }
      defer { session.close() }
      guard let names = try? nativeSessionNames(session) else { return false }
      for host in hosts {
        guard
          (try? NativeHelperClient.send(.init(op: .routeDelete, host: host), socketPath: helper))?
            .ok == true
        else { return false }
      }
      for name in names where name.hasPrefix(namePrefix) {
        guard removeSession(name: name, vici: vici) else { return false }
      }
      return localStateIsEmpty(vici: vici, helper: helper)
    }
  }
}

/// Terminates and unloads one named session; true when nothing of it is left.
@discardableResult
private func removeSession(name: String, vici: String) -> Bool {
  guard let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 8_000) else {
    return false
  }
  defer { session.close() }
  _ = try? session.streamedRequest(
    command: "terminate", event: "control-log",
    message: VICIMessage(elements: [
      .keyValue("ike", name), .keyValue("force", "yes"), .keyValue("timeout", "5000"),
      .keyValue("loglevel", "-1"),
    ]))
  _ = try? session.request(
    command: "unload-conn", message: VICIMessage(elements: [.keyValue("name", name)]))
  _ = try? session.request(
    command: "unload-shared", message: VICIMessage(elements: [.keyValue("id", name)]))
  // Check all three object types, even when an unload response was lost.
  guard let remaining = try? nativeSessionNames(session) else { return false }
  return !remaining.contains(name)
}

private func localStateIsEmpty(vici: String, helper: String) -> Bool {
  guard let status = try? NativeHelperClient.send(.init(op: .status), socketPath: helper),
    status.ok, status.routes?.isEmpty == true,
    let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 5_000)
  else { return false }
  defer { session.close() }
  guard let names = try? nativeSessionNames(session) else { return false }
  return names.allSatisfy { !$0.hasPrefix(NativeTunnel.namePrefix) }
}

/// VICI and the helper socket block; keep them off the cooperative pool.
package func onBlockingThread<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
  await withCheckedContinuation { continuation in
    Thread.detachNewThread { continuation.resume(returning: body()) }
  }
}
