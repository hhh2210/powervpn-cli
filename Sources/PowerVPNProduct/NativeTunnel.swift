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
    case .resourceUnavailable:
      "make `resource` in targets.json match the Portal resource name exactly"
    case .ikeFailed, .childFailed, .routeRejected, .busy, .cancelled: "retry the same command"
    }
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
  private var closed = false

  private init(
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
  ) async -> Result<NativeTunnel, NativeTunnelFailure> {
    if let failure = backendAvailable(helper: helper) { return .failure(failure) }
    guard let target = try? configuration.target(named: targetKey),
      target.resourceDisplayName != nil
    else { return .failure(.targetInvalid) }
    let name = namePrefix + targetKey + "-" + UUID().uuidString.prefix(8).lowercased()

    // A crashed earlier session can leave its connection loaded; the product
    // runs one session at a time, so anything with our prefix is stale.
    await onBlockingThread { removeStaleSessions(vici: vici, helper: helper, host: target.host) }
    if Task.isCancelled { return .failure(.cancelled) }

    // The Portal resource catalog intermittently comes back without the
    // selected resource; a fresh login usually returns it.
    for attempt in 1...portalAttempts {
      guard
        case .acquired(let lease) = await PortalLoginRuntime.acquire(configuration: configuration)
      else { return .failure(.portalRejected) }
      let tunnel = NativeTunnel(
        targetIPv4: target.ipv4, targetHost: target.host, name: name, lease: lease,
        vici: vici, helper: helper)
      let established = await onBlockingThread { tunnel.establish(target: target) }
      if established == nil, !Task.isCancelled { return .success(tunnel) }
      _ = await tunnel.shutdown()
      if Task.isCancelled { return .failure(.cancelled) }
      guard let failure = established else { return .failure(.cancelled) }
      if failure != .resourceUnavailable || attempt == portalAttempts { return .failure(failure) }
      try? await Task.sleep(for: .seconds(2))
    }
    return .failure(.resourceUnavailable)
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
        message: VICIMessage(elements: [.keyValue("ike", name), .keyValue("noblock", "yes")]))
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
    let first = lock.withLock { () -> Bool in
      defer { closed = true }
      return !closed
    }
    guard first else { return true }
    let local = await onBlockingThread { () -> Bool in
      let routeGone =
        (try? NativeHelperClient.send(
          .init(op: .routeDelete, host: self.targetHost), socketPath: self.helper))?.ok == true
      let saGone = removeSession(name: self.name, vici: self.vici)
      return routeGone && saGone
    }
    let logout = await lease.logoutAndErase()
    let portalClosed = logout.status == .accepted || logout.status == .alreadyClosed
    return local && portalClosed
  }
}

extension NativeTunnel {
  /// Removes what a crashed or unverified earlier session may have left: our
  /// host routes for the configured targets and every `powervpn-` SA and
  /// connection. True only when the helper and charon both confirm nothing is left.
  package static func recoverStale(
    configuration: PowerVPNTargetsConfiguration,
    vici: String = NativeHelperPaths.vici,
    helper: String = NativeHelperPaths.control
  ) async -> Bool {
    let hosts = configuration.configuredTargetKeys.compactMap {
      try? configuration.target(named: $0).host
    }
    return await onBlockingThread {
      for host in hosts { removeStaleSessions(vici: vici, helper: helper, host: host) }
      guard
        let status = try? NativeHelperClient.send(.init(op: .status), socketPath: helper),
        status.ok, (status.routes ?? []).allSatisfy({ !hosts.contains($0) }),
        let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 5_000),
        let sas = try? session.streamedRequest(
          command: "list-sas", event: "list-sa",
          message: VICIMessage(elements: [.keyValue("noblock", "yes")]))
      else { return false }
      session.close()
      return NativeIKESummary.parse(sas.events).allSatisfy { !$0.name.hasPrefix(namePrefix) }
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
  guard
    let remaining = try? session.streamedRequest(
      command: "list-sas", event: "list-sa",
      message: VICIMessage(elements: [.keyValue("ike", name), .keyValue("noblock", "yes")]))
  else { return false }
  return NativeIKESummary.parse(remaining.events).allSatisfy { $0.name != name }
}

private func removeStaleSessions(vici: String, helper: String, host: String) {
  _ = try? NativeHelperClient.send(.init(op: .routeDelete, host: host), socketPath: helper)
  guard let session = try? VICISession(socketPath: vici, timeoutMilliseconds: 5_000) else {
    return
  }
  var names = Set<String>()
  if let sas = try? session.streamedRequest(
    command: "list-sas", event: "list-sa",
    message: VICIMessage(elements: [.keyValue("noblock", "yes")]))
  {
    for ike in NativeIKESummary.parse(sas.events) { names.insert(ike.name) }
  }
  if let conns = try? session.request(command: "get-conns"),
    let list = conns.message.elements.first(where: {
      if case .list("conns", _) = $0 { return true }
      return false
    }), case .list(_, let values) = list
  {
    for value in values { names.insert(String(decoding: value, as: UTF8.self)) }
  }
  session.close()
  for name in names where name.hasPrefix(NativeTunnel.namePrefix) {
    removeSession(name: name, vici: vici)
  }
}

/// VICI and the helper socket block; keep them off the cooperative pool.
package func onBlockingThread<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
  await withCheckedContinuation { continuation in
    Thread.detachNewThread { continuation.resume(returning: body()) }
  }
}
