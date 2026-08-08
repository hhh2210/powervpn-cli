import Foundation
import Network

private final class CompletionGate: @unchecked Sendable {
  private let lock = NSLock()
  private var completed = false

  func runOnce(_ body: () -> Void) {
    lock.lock()
    defer { lock.unlock() }
    guard !completed else { return }
    completed = true
    body()
  }
}

public enum SSHBannerClassifier {
  public static func classify(_ data: Data) -> (ProbeStatus, String) {
    let banner = String(decoding: data.prefix(255), as: UTF8.self)
      .trimmingCharacters(in: .whitespacesAndNewlines)
    if banner.hasPrefix("SSH-") {
      return (.healthy, banner)
    }
    if banner.isEmpty {
      return (.bannerTimeout, "connected, but no SSH banner received")
    }
    return (.nonSSHBanner, banner)
  }
}

public struct SSHBannerProbe: Sendable {
  public init() {}

  public func probe(target: VPNTarget, timeout: TimeInterval = 5) async -> ProbeResult {
    await withCheckedContinuation { continuation in
      let started = ContinuousClock.now
      let queue = DispatchQueue(label: "powervpn.probe.\(target.name)")
      let gate = CompletionGate()
      let connection = NWConnection(
        host: NWEndpoint.Host(target.host),
        port: NWEndpoint.Port(rawValue: target.port)!,
        using: .tcp
      )

      let finish: @Sendable (ProbeStatus, String) -> Void = { status, detail in
        gate.runOnce {
          let duration = ContinuousClock.now - started
          let milliseconds =
            Int(duration.components.seconds * 1_000)
            + Int(duration.components.attoseconds / 1_000_000_000_000_000)
          connection.cancel()
          continuation.resume(
            returning: ProbeResult(
              target: target,
              status: status,
              latencyMilliseconds: milliseconds,
              detail: detail
            ))
        }
      }

      connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
          connection.receive(minimumIncompleteLength: 1, maximumLength: 255) {
            data, _, _, error in
            if let error {
              finish(.connectionFailed, error.localizedDescription)
              return
            }
            let (status, detail) = SSHBannerClassifier.classify(data ?? Data())
            finish(status, detail)
          }
        case .failed(let error):
          finish(.connectionFailed, error.localizedDescription)
        case .waiting(let error):
          finish(.connectionFailed, error.localizedDescription)
        default:
          break
        }
      }

      queue.asyncAfter(deadline: .now() + timeout) {
        finish(.bannerTimeout, "timed out waiting for SSH banner")
      }
      connection.start(queue: queue)
    }
  }
}
