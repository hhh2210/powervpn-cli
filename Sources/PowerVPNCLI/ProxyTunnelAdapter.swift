import Foundation
import PowerVPNPortal
import PowerVPNProduct

struct ProxyCommandResult: Equatable, Sendable {
  let standardOutput: String
  let standardError: String
  let exitCode: Int32
  let cleanupReceipt: ProductPersistentTunnelShutdownReport?

  init(
    standardOutput: String,
    standardError: String,
    exitCode: Int32,
    cleanupReceipt: ProductPersistentTunnelShutdownReport? = nil
  ) {
    self.standardOutput = standardOutput
    self.standardError = standardError
    self.exitCode = exitCode
    self.cleanupReceipt = cleanupReceipt
  }
}

struct ProxyTunnelShutdown: Equatable, Sendable {
  let cleanupVerified: Bool
  let cleanupReceipt: ProductPersistentTunnelShutdownReport?

  init(
    cleanupVerified: Bool,
    cleanupReceipt: ProductPersistentTunnelShutdownReport? = nil
  ) {
    self.cleanupVerified = cleanupVerified
    self.cleanupReceipt = cleanupReceipt
  }

  init(receipt: ProductPersistentTunnelShutdownReport) {
    cleanupVerified = receipt.cleanupVerified
    cleanupReceipt = receipt
  }
}

protocol ProxyTunnelLeasing: Sendable {
  func permitsIPv4(_ address: UInt32) async -> Bool
  func shutdown(budget: ProductM2CleanupBudget) async -> ProxyTunnelShutdown
}

struct ProxyTunnelOpenFailure: Equatable, Sendable {
  let failure: ProductM2ConnectOutcome?
  var firstBadEvent: ProductM2BadEvent? = nil
  var selectionFailureClass: ProductM2SelectionFailureClass? = nil
  var resourceCatalogFailure: ProductResourceCatalogFailure? = nil
  var nativeFailure: NativeTunnelFailure? = nil
  let helperMutationRequested: Bool
  let serverContactRequested: Bool
  let cleanupVerified: Bool
  var cleanupReceipt: ProductPersistentTunnelShutdownReport? = nil
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
        selectionFailureClass: report.selectionFailureClass,
        resourceCatalogFailure: report.resourceCatalogFailure,
        helperMutationRequested: report.helperMutationRequested,
        serverContactRequested: report.serverContactRequested,
        cleanupVerified: report.cleanupVerified,
        cleanupReceipt: report.cleanupReceipt
      ))
  }
}
/// Native backend: the mutation lease is held for the whole session, exactly
/// like the vendor runtime, so `up`/`run`/`down` see the same busy signal.
func openNativeProxyTunnel(
  configuration: PowerVPNTargetsConfiguration,
  request: ProductM2ConnectRequest
) async -> ProxyTunnelOpenResult {
  guard let mutationLease = try? ProductMutationLease.acquireCurrentMachine() else {
    return .failed(nativeOpenFailure(.busy))
  }
  switch await NativeTunnel.open(
    configuration: configuration, targetKey: request.sshTarget.rawValue)
  {
  case .success(let tunnel):
    return .opened(
      NativeProxyTunnelLease(tunnel: tunnel, mutationLease: mutationLease),
      helperMutationRequested: true,
      serverContactRequested: true
    )
  case .failure(let failure):
    withExtendedLifetime(mutationLease) {}
    return .failed(nativeOpenFailure(failure))
  }
}

private func nativeOpenFailure(_ failure: NativeTunnelFailure) -> ProxyTunnelOpenFailure {
  // NativeTunnel.open removes whatever it created before it reports a failure.
  ProxyTunnelOpenFailure(
    failure: failure == .cancelled ? .cancelled : nil,
    nativeFailure: failure,
    helperMutationRequested: false,
    serverContactRequested: failure != .helperUnavailable && failure != .charonUnavailable,
    cleanupVerified: true
  )
}

private final class NativeProxyTunnelLease: ProxyTunnelLeasing, @unchecked Sendable {
  let tunnel: NativeTunnel
  private var mutationLease: ProductMutationLease?
  private let lock = NSLock()

  init(tunnel: NativeTunnel, mutationLease: ProductMutationLease) {
    self.tunnel = tunnel
    self.mutationLease = mutationLease
  }

  func permitsIPv4(_ address: UInt32) async -> Bool {
    address == tunnel.targetIPv4
  }

  func shutdown(budget _: ProductM2CleanupBudget) async -> ProxyTunnelShutdown {
    let verified = await tunnel.shutdown()
    lock.withLock { mutationLease = nil }
    return ProxyTunnelShutdown(cleanupVerified: verified)
  }
}

private struct ProductProxyTunnelLease: ProxyTunnelLeasing {
  let lease: ProductPersistentTunnelLease

  func permitsIPv4(_ address: UInt32) async -> Bool {
    await lease.permitsIPv4(address)
  }

  func shutdown(budget: ProductM2CleanupBudget) async -> ProxyTunnelShutdown {
    let report = await lease.shutdown(budget: budget)
    return ProxyTunnelShutdown(receipt: report)
  }
}
