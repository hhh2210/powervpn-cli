import Foundation
import PowerVPNProduct

/// The token a proxy reports when its watchdog ended the session.
let proxyTunnelLostToken = "tunnel_lost"

/// How often the owning process probes its tunnel, and how many absent results
/// in a row confirm the loss. The run of three rides over a gap in which charon
/// briefly lists no SA.
struct ProxyTunnelWatchPolicy: Equatable, Sendable {
  let interval: Duration
  let absentThreshold: Int

  static let standard = Self(interval: .seconds(5), absentThreshold: 3)
}

private enum ProxyTunnelWatchEvent: Sendable {
  case child(ProxyChildRunResult)
  case lost
  case watchEnded
}

/// Runs `child` while probing the lease's tunnel. Nothing else notices a tunnel
/// that died under a live ssh: the child keeps waiting on a TCP connection that
/// can no longer carry anything. On confirmed loss only the child is stopped,
/// so the caller's normal shutdown and receipt path still runs. A backend
/// without a probe just runs the child.
func runChildWatchingTunnel(
  lease: any ProxyTunnelLeasing,
  policy: ProxyTunnelWatchPolicy,
  child: @escaping @Sendable () async -> ProxyChildRunResult
) async -> ProxyLeaseOperationResult {
  await withTaskGroup(of: ProxyTunnelWatchEvent.self) { group in
    group.addTask { .child(await child()) }
    group.addTask {
      var detector = NativeTunnelLossDetector(threshold: policy.absentThreshold)
      while let liveness = await lease.liveness() {
        // The probe blocks on a socket; a child that ended meanwhile wins.
        if Task.isCancelled { break }
        if detector.observe(liveness) {
          await lease.tunnelLost(consecutiveAbsent: detector.consecutiveAbsent)
          return .lost
        }
        do { try await Task.sleep(for: policy.interval) } catch { break }
      }
      return .watchEnded
    }
    var lost = false
    var childResult = ProxyChildRunResult(outcome: .cancelled, becameReady: false)
    for await event in group {
      switch event {
      case .child(let result):
        childResult = result
        group.cancelAll()
      case .lost:
        lost = true
        group.cancelAll()
      case .watchEnded:
        break
      }
    }
    // A child that finished on its own just as the loss was confirmed keeps
    // its own result.
    return lost && childResult.outcome == .cancelled ? .tunnelLost : .child(childResult)
  }
}
