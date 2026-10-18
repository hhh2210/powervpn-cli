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
  case routeRejected = "native_route_rejected"
  case busy = "native_session_busy"
  case cancelled = "native_cancelled"

  package var next: String {
    switch self {
    case .helperUnavailable, .charonUnavailable:
      "install or restart the native backend: sudo scripts/native/install.sh"
    case .targetInvalid: "fix the target in ~/.config/powervpn/targets.json"
    case .portalRejected: "check ~/.config/powervpn/credentials.env and the Portal account"
    case .portalConfigurationRejected: "check the Portal origin and TLS trust in targets.json"
    case .cleanupUnproven: "powervpn down (inspect local recovery and Portal cleanup separately)"
    case .resourceUnavailable:
      "make `resource` in targets.json match the Portal resource name exactly"
    case .portalUnavailable, .ikeFailed, .childFailed, .routeRejected, .busy, .cancelled:
      "retry the same command"
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

package struct NativeTunnelOpenFailure: Error, Equatable, Sendable {
  package let failure: NativeTunnelFailure
  package var helperMutationRequested = false
  package var serverContactRequested = false
  package var cleanupVerified = true

  package init(
    failure: NativeTunnelFailure, helperMutationRequested: Bool = false,
    serverContactRequested: Bool = false, cleanupVerified: Bool = true
  ) {
    self.failure = failure
    self.helperMutationRequested = helperMutationRequested
    self.serverContactRequested = serverContactRequested
    self.cleanupVerified = cleanupVerified
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

/// Everything one native session owns, so shutdown can remove exactly that.
package final class NativeTunnel: @unchecked Sendable {
  package static let namePrefix = "powervpn-"

  package let targetIPv4: UInt32
  private let targetHost: String
  private let name: String
  private let lease: AuthenticatedPortalLease
  private let vici: String
  private let helper: String
  private let lock = NSLock()
  private var shutdownTask: Task<Bool, Never>?
  private var mutationRequested = false

  init(
    targetIPv4: UInt32, targetHost: String, name: String, lease: AuthenticatedPortalLease,
    vici: String, helper: String
  ) {
    self.targetIPv4 = targetIPv4
    self.targetHost = targetHost
    self.name = name
    self.lease = lease
    self.vici = vici
    self.helper = helper
  }

  /// True when the root helper and charon are both up.
  package static func backendAvailable(
    helper: String = NativeHelperPaths.control
  ) -> NativeTunnelFailure? {
    guard let status = try? NativeHelperClient.send(.init(op: .status), socketPath: helper),
      status.ok
    else { return .helperUnavailable }
    return status.charonRunning == true ? nil : .charonUnavailable
  }

  package static func open(
    configuration: PowerVPNTargetsConfiguration,
    targetKey: String,
    vici: String = NativeHelperPaths.vici,
    helper: String = NativeHelperPaths.control
  ) async -> Result<NativeTunnel, NativeTunnelOpenFailure> {
    if let failure = backendAvailable(helper: helper) { return .failure(.init(failure: failure)) }
    guard let target = try? configuration.target(named: targetKey),
      target.resourceDisplayName != nil
    else { return .failure(.init(failure: .targetInvalid)) }
    let name = namePrefix + targetKey + "-" + UUID().uuidString.prefix(8).lowercased()

    // Cleanup of an earlier owner belongs to explicit, leased recovery. A
    // standalone proxy must not silently erase that owner's cleanup evidence.
    let empty = await onBlockingThread { localStateIsEmpty(vici: vici, helper: helper) }
    guard empty else {
      return .failure(.init(failure: .cleanupUnproven, cleanupVerified: false))
    }
    if Task.isCancelled { return .failure(.init(failure: .cancelled)) }

    // The Portal resource catalog intermittently comes back without the
    // selected resource; a fresh login usually returns it.
    for attempt in 1...portalAttempts {
      let lease: AuthenticatedPortalLease
      switch await PortalLoginRuntime.acquire(configuration: configuration) {
      case .acquired(let acquired): lease = acquired
      case .rejected(let report):
        return .failure(.init(portal: report))
      }
      let tunnel = NativeTunnel(
        targetIPv4: target.ipv4, targetHost: target.host, name: name, lease: lease,
        vici: vici, helper: helper)
      let established = await onBlockingThread { tunnel.establish(target: target) }
      if established == nil, !Task.isCancelled { return .success(tunnel) }
      let cleaned = await tunnel.shutdown()
      let failure: NativeTunnelFailure = Task.isCancelled ? .cancelled : (established ?? .cancelled)
      guard cleaned else {
        return .failure(
          .init(
            failure: failure, helperMutationRequested: tunnel.mutationRequested,
            serverContactRequested: true, cleanupVerified: false))
      }
      if failure != .resourceUnavailable || attempt == portalAttempts {
        return .failure(
          .init(
            failure: failure, helperMutationRequested: tunnel.mutationRequested,
            serverContactRequested: true, cleanupVerified: true))
      }
      try? await Task.sleep(for: .seconds(2))
      if Task.isCancelled {
        return .failure(.init(failure: .cancelled, serverContactRequested: true))
      }
    }
    return .failure(.init(failure: .resourceUnavailable, serverContactRequested: true))
  }

  private static let portalAttempts = 3

  private func establish(target: PowerVPNTargetConfiguration) -> NativeTunnelFailure? {
    guard let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 25_000) else {
      return .charonUnavailable
    }
    defer { session.close() }
    do {
      try NativeTrialPortalBridge.withRequests(
        snapshot: lease.snapshot, target: target, name: name, includePrivateRule: true
      ) { shared, connection in
        // A timeout after sending a request can still have mutated charon.
        mutationRequested = true
        _ = try session.request(command: "load-shared", message: shared)
        _ = try session.request(command: "load-conn", message: connection)
      }
    } catch is NativeTrialPortalBridge.Failure {
      return .resourceUnavailable
    } catch is NativeTrialMaterial.Failure {
      return .resourceUnavailable
    } catch {
      return .ikeFailed
    }
    do {
      _ = try session.streamedRequest(
        command: "initiate", event: "control-log",
        message: VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("timeout", "15000"), .keyValue("loglevel", "-1"),
        ]))
    } catch { return .ikeFailed }
    guard let ike = summary(session), ike.state == "ESTABLISHED" else { return .ikeFailed }
    do {
      _ = try session.streamedRequest(
        command: "initiate", event: "control-log",
        message: VICIMessage(elements: [
          .keyValue("ike", name), .keyValue("child", NativeTrialMaterial.childName),
          .keyValue("timeout", "15000"), .keyValue("loglevel", "-1"),
        ]))
    } catch { return .childFailed }
    guard summary(session)?.hasInstalledChild == true else { return .childFailed }
    guard
      let routed = try? NativeHelperClient.send(
        .init(op: .routeAdd, ike: name, host: targetHost), socketPath: helper),
      routed.ok
    else { return .routeRejected }
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

  /// True while the IKE SA still carries an installed child.
  package func isAlive() async -> Bool {
    await onBlockingThread {
      guard let session = try? VICISession(socketPath: self.vici, timeoutMilliseconds: 3_000)
      else { return false }
      defer { session.close() }
      return self.summary(session)?.hasInstalledChild == true
    }
  }

  /// Removes the route, the SA, the loaded connection and the Portal session.
  /// Returns true only when each of them is verified gone.
  package func shutdown() async -> Bool {
    let task = lock.withLock { () -> Task<Bool, Never> in
      if let shutdownTask { return shutdownTask }
      let task = Task.detached { await self.performShutdown() }
      shutdownTask = task
      return task
    }
    return await task.value
  }

  private func performShutdown() async -> Bool {
    let local = await onBlockingThread { () -> Bool in
      if !self.mutationRequested { return true }
      let routeGone =
        (try? NativeHelperClient.send(
          .init(op: .routeDelete, host: self.targetHost), socketPath: self.helper))?.ok == true
      let saGone = removeSession(name: self.name, vici: self.vici)
      return routeGone && saGone
    }
    let logout = await lease.logoutAndErase()
    let portalClosed = logout.status == .accepted && logout.failureClass == .completedRemoteExchange
    return local && portalClosed
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

func nativeSessionNames(_ session: VICISession) throws -> Set<String> {
  var names = Set<String>()
  let sas = try session.streamedRequest(command: "list-sas", event: "list-sa")
  for ike in NativeIKESummary.parse(sas.events) { names.insert(ike.name) }
  for (command, key) in [("get-conns", "conns"), ("get-shared", "keys")] {
    let result = try session.request(command: command)
    guard
      let element = result.message.elements.first(where: {
        if case .list(key, _) = $0 { return true }
        return false
      }), case .list(_, let values) = element
    else { throw VICISessionError.commandFailed(command) }
    for value in values { names.insert(String(decoding: value, as: UTF8.self)) }
  }
  return names
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
