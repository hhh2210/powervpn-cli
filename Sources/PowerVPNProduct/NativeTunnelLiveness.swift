import Foundation
import PowerVPNCore

/// What one VICI `list-sas` round trip proves about a native session.
package enum NativeTunnelLiveness: String, Equatable, Sendable {
  /// An IKE SA of the session carries an INSTALLED child.
  case installed
  /// charon answered and holds no IKE SA of the session: it was deleted, or
  /// charon itself restarted. The only result that is evidence of loss.
  case absent
  /// No proof either way: VICI was unreachable or timed out, or an IKE SA
  /// exists without an INSTALLED child, which is what a rekey can look like.
  case unknown

  /// `summaries` is nil when the query itself failed.
  package static func classify(
    _ summaries: [NativeIKESummary]?, matches: (String) -> Bool
  ) -> Self {
    guard let summaries else { return .unknown }
    let own = summaries.filter { matches($0.name) }
    if own.isEmpty { return .absent }
    return own.contains { $0.hasInstalledChild } ? .installed : .unknown
  }
}

/// Decides when a session is lost. Only an uninterrupted run of `absent`
/// results counts: an unreachable charon must never end a healthy session,
/// because long remote commands share it.
package struct NativeTunnelLossDetector: Equatable, Sendable {
  package let threshold: Int
  package private(set) var consecutiveAbsent = 0

  package init(threshold: Int) {
    self.threshold = max(1, threshold)
  }

  /// Feeds one probe result; true once the loss is confirmed.
  package mutating func observe(_ liveness: NativeTunnelLiveness) -> Bool {
    switch liveness {
    case .absent: consecutiveAbsent += 1
    case .installed, .unknown: consecutiveAbsent = 0
    }
    return consecutiveAbsent >= threshold
  }
}

extension NativeTunnel {
  /// One `list-sas` over every SA; `matches` selects the session's own.
  package static func liveness(
    vici: String = NativeHelperPaths.vici, timeoutMilliseconds: Int = 3_000,
    matches: (String) -> Bool
  ) -> NativeTunnelLiveness {
    guard let session = try? VICISession(socketPath: vici, timeoutMilliseconds: timeoutMilliseconds)
    else { return .unknown }
    defer { session.close() }
    let result = try? session.streamedRequest(command: "list-sas", event: "list-sa")
    return .classify(result.map { NativeIKESummary.parse($0.events) }, matches: matches)
  }

  /// For a process that does not own the session and so does not know its
  /// name: `open` refuses to start over leftovers, so at most one session of a
  /// target exists.
  package static func liveness(
    target: String, vici: String = NativeHelperPaths.vici
  ) async -> NativeTunnelLiveness {
    let prefix = namePrefix + target + "-"
    return await onBlockingThread { liveness(vici: vici) { $0.hasPrefix(prefix) } }
  }
}
