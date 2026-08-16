import PowerVPNProduct

struct ProxyCommandResult: Equatable, Sendable {
  let standardOutput: String
  let standardError: String
  let exitCode: Int32
}

struct ProxyTunnelShutdown: Equatable, Sendable {
  let cleanupVerified: Bool
}

protocol ProxyTunnelLeasing: Sendable {
  func permitsIPv4(_ address: UInt32) async -> Bool
  func shutdown(budget: ProductM2CleanupBudget) async -> ProxyTunnelShutdown
}

struct ProxyTunnelOpenFailure: Equatable, Sendable {
  let failure: ProductM2ConnectOutcome?
  var firstBadEvent: ProductM2BadEvent? = nil
  let helperMutationRequested: Bool
  let serverContactRequested: Bool
  let cleanupVerified: Bool
}

enum ProxyTunnelOpenResult: Sendable {
  case opened(
    any ProxyTunnelLeasing,
    helperMutationRequested: Bool,
    serverContactRequested: Bool
  )
  case failed(ProxyTunnelOpenFailure)
}

typealias ProxyTunnelOpenOperation =
  @Sendable (ProductM2ConnectRequest, ProductM2AbsoluteBudget) async -> ProxyTunnelOpenResult

func openProductProxyTunnel(
  runtime: ProductPersistentTunnelRuntime,
  request: ProductM2ConnectRequest,
  budget: ProductM2AbsoluteBudget
) async -> ProxyTunnelOpenResult {
  switch await runtime.open(request: request, startupBudget: budget) {
  case .opened(let lease, let report):
    return .opened(
      ProductProxyTunnelLease(lease: lease),
      helperMutationRequested: report.helperMutationRequested,
      serverContactRequested: report.serverContactRequested
    )
  case .failed(let report):
    return .failed(
      ProxyTunnelOpenFailure(
        failure: report.failure,
        firstBadEvent: report.firstBadEvent,
        helperMutationRequested: report.helperMutationRequested,
        serverContactRequested: report.serverContactRequested,
        cleanupVerified: report.cleanupVerified
      ))
  }
}
private struct ProductProxyTunnelLease: ProxyTunnelLeasing {
  let lease: ProductPersistentTunnelLease

  func permitsIPv4(_ address: UInt32) async -> Bool {
    await lease.permitsIPv4(address)
  }

  func shutdown(budget: ProductM2CleanupBudget) async -> ProxyTunnelShutdown {
    let report = await lease.shutdown(budget: budget)
    return ProxyTunnelShutdown(cleanupVerified: report.cleanupVerified)
  }
}
