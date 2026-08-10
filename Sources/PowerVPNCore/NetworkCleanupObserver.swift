import Foundation

package protocol NetworkCleanupObserving: Sendable {
  func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?
  ) async -> NetworkCleanupSnapshot
}

package struct InstalledNetworkCleanupObserver: NetworkCleanupObserving {
  private let runner: any NetworkCleanupCommandRunning

  package init() {
    runner = InstalledNetworkCleanupCommandRunner()
  }

  init(runner: any NetworkCleanupCommandRunning) {
    self.runner = runner
  }

  package func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil
  ) async -> NetworkCleanupSnapshot {
    let helperBefore = await helper()
    let processesBefore = await processes(window: window)
    let defaultRoute = await fingerprint(.defaultRoute) {
      try NetworkDefaultRouteCanonicalizer.canonicalize($0)
    }
    let dns = await fingerprint(.dns) {
      try NetworkDNSCanonicalizer.canonicalize($0)
    }
    let interfaces = await interfaceSnapshot(window: window)
    let ipv4 = await routeSnapshot(.ipv4Routes, family: .inet, selectedRoutes: selectedRoutes)
    let ipv6 = await routeSnapshot(.ipv6Routes, family: .inet6, selectedRoutes: nil)
    let processesAfter = await processes(window: window)
    let helperAfter = await helper()

    let stableSurge: NetworkCleanupSurgeSnapshot
    switch (processesBefore, processesAfter) {
    case (.success(let before), .success(let after)) where before == after:
      stableSurge = before.surge
    case (.success, .success):
      stableSurge = .unavailable(.changedDuringCapture)
    case (.failure(let state), _), (_, .failure(let state)):
      stableSurge = .unavailable(state)
    }

    let stableVendorProcesses: NetworkCleanupVendorProcessSnapshot
    switch (processesBefore, processesAfter) {
    case (.success(let before), .success(let after)) where before == after:
      stableVendorProcesses = before.vendor
    case (.success, .success):
      stableVendorProcesses = .unavailable(.changedDuringCapture)
    case (.failure(let state), _), (_, .failure(let state)):
      stableVendorProcesses = .unavailable(state)
    }

    let generation: VendorHelperGenerationSnapshot
    let helperState: NetworkCleanupObservationState
    switch (helperBefore, helperAfter) {
    case (.success(let before), .success(let after)) where before == after:
      generation = before
      helperState = .observed
    case (.success(let before), .success):
      generation = before
      helperState = .changedDuringCapture
    case (.success(let before), .failure(let state)):
      generation = before
      helperState = state
    case (.failure(let state), .success(let after)):
      generation = after
      helperState = state
    case (.failure(let beforeState), .failure(let afterState)):
      generation = .unavailable
      helperState = beforeState == afterState ? beforeState : .changedDuringCapture
    }

    return NetworkCleanupSnapshot(
      defaultRoute: defaultRoute,
      dns: dns,
      interfaces: interfaces,
      ipv4Routes: ipv4,
      ipv6Routes: ipv6,
      surge: stableSurge,
      vendorProcesses: stableVendorProcesses,
      helperGeneration: generation,
      helperObservationState: helperState
    )
  }

  private func fingerprint(
    _ command: NetworkCleanupCommand,
    parser: (Data) throws -> NetworkCleanupFingerprint
  ) async -> NetworkCleanupFingerprint {
    let result = await runner.run(command)
    guard result.succeeded else {
      return .unavailable(NetworkCleanupCommandOutput.state(result))
    }
    do { return try parser(result.stdout) } catch { return .unavailable(.invalidOutput) }
  }

  private func interfaceSnapshot(
    window: NetworkCleanupCaptureWindow
  ) async -> NetworkCleanupInterfaceSnapshot {
    let result = await runner.run(.interfaces)
    guard result.succeeded else {
      return .unavailable(NetworkCleanupCommandOutput.state(result))
    }
    do {
      return try NetworkInterfaceCanonicalizer.canonicalize(result.stdout, window: window)
    } catch {
      return .unavailable(.invalidOutput)
    }
  }

  private func routeSnapshot(
    _ command: NetworkCleanupCommand,
    family: NetworkRouteFamily,
    selectedRoutes: VendorCharonSelectedRouteMatcher?
  ) async -> NetworkCleanupRouteSnapshot {
    let result = await runner.run(command)
    guard result.succeeded else {
      return .unavailable(NetworkCleanupCommandOutput.state(result))
    }
    do {
      let routes = try NetworkRouteCanonicalizer.parse(result.stdout, family: family)
      let effectiveRoute = await effectiveRouteSnapshot(selectedRoutes, routes: routes)
      return try NetworkRouteCanonicalizer.canonicalize(
        result.stdout,
        family: family,
        selectedRoutes: selectedRoutes,
        effectiveSelectedRoute: effectiveRoute
      )
    } catch {
      return .unavailable(.invalidOutput)
    }
  }

  private func effectiveRouteSnapshot(
    _ matcher: VendorCharonSelectedRouteMatcher?,
    routes: [NetworkCanonicalRoute]
  ) async -> NetworkCleanupEffectiveRouteSnapshot? {
    guard let matcher else { return nil }
    let result = await runner.run(matcher.effectiveRouteCommand)
    guard result.succeeded else {
      return .unavailable(NetworkCleanupCommandOutput.state(result))
    }
    do {
      return try NetworkCleanupEffectiveRouteCanonicalizer.canonicalize(
        result.stdout,
        matcher: matcher,
        routes: routes
      )
    } catch {
      return .unavailable(.invalidOutput)
    }
  }

  private func processes(
    window: NetworkCleanupCaptureWindow
  ) async -> Result<NetworkCleanupProcessInventory, NetworkCleanupObservationState> {
    let result = await runner.run(.surgeProcesses)
    guard result.succeeded else {
      return .failure(NetworkCleanupCommandOutput.state(result))
    }
    do {
      return .success(
        NetworkCleanupProcessInventory(
          surge: try NetworkSurgeProcessCanonicalizer.canonicalize(result.stdout),
          vendor: try NetworkVendorProcessCanonicalizer.canonicalize(
            result.stdout,
            window: window
          )
        ))
    } catch {
      return .failure(.invalidOutput)
    }
  }

  private func helper() async
    -> Result<VendorHelperGenerationSnapshot, NetworkCleanupObservationState>
  {
    let result = await runner.run(.helperGeneration)
    guard result.succeeded else {
      return .failure(NetworkCleanupCommandOutput.state(result))
    }
    guard let output = String(data: result.stdout, encoding: .utf8),
      !result.stdout.contains(0)
    else { return .failure(.invalidOutput) }
    let snapshot = LaunchdVendorHelperSnapshotParser.parse(output)
    guard snapshot.exactInactive || snapshot.exactRunning else {
      return .failure(.invalidOutput)
    }
    return .success(snapshot)
  }
}

private struct NetworkCleanupProcessInventory: Equatable, Sendable {
  let surge: NetworkCleanupSurgeSnapshot
  let vendor: NetworkCleanupVendorProcessSnapshot
}
