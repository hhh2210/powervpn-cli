import Foundation

package protocol NetworkCleanupObserving: Sendable {
  func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    timeoutMilliseconds: Int
  ) async -> NetworkCleanupSnapshot
}

extension NetworkCleanupObserving {
  package func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher? = nil
  ) async -> NetworkCleanupSnapshot {
    await capture(
      window: window,
      selectedRoutes: selectedRoutes,
      timeoutMilliseconds: 24_000
    )
  }
}

package struct InstalledNetworkCleanupObserver: NetworkCleanupObserving {
  private let runner: any NetworkCleanupCommandRunning
  private let monotonicNowNanoseconds: @Sendable () -> UInt64

  package init() {
    runner = InstalledNetworkCleanupCommandRunner()
    monotonicNowNanoseconds = { DispatchTime.now().uptimeNanoseconds }
  }

  init(
    runner: any NetworkCleanupCommandRunning,
    monotonicNowNanoseconds: @escaping @Sendable () -> UInt64 = {
      DispatchTime.now().uptimeNanoseconds
    }
  ) {
    self.runner = runner
    self.monotonicNowNanoseconds = monotonicNowNanoseconds
  }

  package func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    timeoutMilliseconds: Int
  ) async -> NetworkCleanupSnapshot {
    let budget = NetworkCleanupCommandBudget(
      timeoutMilliseconds: timeoutMilliseconds,
      monotonicNowNanoseconds: monotonicNowNanoseconds
    )
    do {
      return try await capture(
        window: window,
        selectedRoutes: selectedRoutes,
        budget: budget
      )
    } catch {
      return .unavailable(.commandFailed)
    }
  }

  private func capture(
    window: NetworkCleanupCaptureWindow,
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    budget: NetworkCleanupCommandBudget
  ) async throws -> NetworkCleanupSnapshot {
    let helperBefore = try await helper(budget: budget)
    let processesBefore = try await processes(window: window, budget: budget)
    let defaultRoute = try await fingerprint(.defaultRoute, budget: budget) {
      try NetworkDefaultRouteCanonicalizer.canonicalize($0)
    }
    let dns = try await fingerprint(.dns, budget: budget) {
      try NetworkDNSCanonicalizer.canonicalize($0)
    }
    let interfaces = try await interfaceSnapshot(window: window, budget: budget)
    let ipv4 = try await routeSnapshot(
      .ipv4Routes,
      family: .inet,
      selectedRoutes: selectedRoutes,
      budget: budget
    )
    let ipv6 = try await routeSnapshot(
      .ipv6Routes,
      family: .inet6,
      selectedRoutes: nil,
      budget: budget
    )
    let processesAfter = try await processes(window: window, budget: budget)
    let helperAfter = try await helper(budget: budget)
    guard budget.nextCommandTimeoutMilliseconds() != nil else {
      throw NetworkCleanupBudgetError.expired
    }

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
    budget: NetworkCleanupCommandBudget,
    parser: (Data) throws -> NetworkCleanupFingerprint
  ) async throws -> NetworkCleanupFingerprint {
    let result = try await run(command, budget: budget)
    guard result.succeeded else {
      return .unavailable(NetworkCleanupCommandOutput.state(result))
    }
    do { return try parser(result.stdout) } catch { return .unavailable(.invalidOutput) }
  }

  private func interfaceSnapshot(
    window: NetworkCleanupCaptureWindow,
    budget: NetworkCleanupCommandBudget
  ) async throws -> NetworkCleanupInterfaceSnapshot {
    let result = try await run(.interfaces, budget: budget)
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
    selectedRoutes: VendorCharonSelectedRouteMatcher?,
    budget: NetworkCleanupCommandBudget
  ) async throws -> NetworkCleanupRouteSnapshot {
    let result = try await run(command, budget: budget)
    guard result.succeeded else {
      return .unavailable(NetworkCleanupCommandOutput.state(result))
    }
    let routes: [NetworkCanonicalRoute]
    do {
      routes = try NetworkRouteCanonicalizer.parse(result.stdout, family: family)
    } catch {
      return .unavailable(.invalidOutput)
    }
    let effectiveRoute = try await effectiveRouteSnapshot(
      selectedRoutes,
      routes: routes,
      budget: budget
    )
    do {
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
    routes: [NetworkCanonicalRoute],
    budget: NetworkCleanupCommandBudget
  ) async throws -> NetworkCleanupEffectiveRouteSnapshot? {
    guard let matcher else { return nil }
    let result = try await run(matcher.effectiveRouteCommand, budget: budget)
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
    window: NetworkCleanupCaptureWindow,
    budget: NetworkCleanupCommandBudget
  ) async throws
    -> Result<NetworkCleanupProcessInventory, NetworkCleanupObservationState>
  {
    let result = try await run(.surgeProcesses, budget: budget)
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

  private func helper(
    budget: NetworkCleanupCommandBudget
  ) async throws
    -> Result<VendorHelperGenerationSnapshot, NetworkCleanupObservationState>
  {
    let result = try await run(.helperGeneration, budget: budget)
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

  private func run(
    _ command: NetworkCleanupCommand,
    budget: NetworkCleanupCommandBudget
  ) async throws -> BoundedCommandResult {
    guard let timeoutMilliseconds = budget.nextCommandTimeoutMilliseconds() else {
      throw NetworkCleanupBudgetError.expired
    }
    return await runner.run(
      command,
      timeoutMilliseconds: timeoutMilliseconds
    )
  }
}

private struct NetworkCleanupProcessInventory: Equatable, Sendable {
  let surge: NetworkCleanupSurgeSnapshot
  let vendor: NetworkCleanupVendorProcessSnapshot
}
