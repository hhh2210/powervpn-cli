import Foundation

/// When the root helper may restart its charon on request. The decision is a
/// pure function of what the helper observed, so it is testable without root.
public struct NativeCharonRestartGovernor: Sendable {
  public enum Refusal: String, Equatable, Sendable {
    /// A session, connection, key or route of ours exists: restarting drops it.
    case notIdle = "not_idle"
    /// The idle check itself failed; absence of proof is not idleness.
    case idleUnknown = "idle_unknown"
    case tooSoon = "too_soon"
    case budgetExhausted = "budget_exhausted"
  }

  public enum Decision: Equatable, Sendable {
    case allow
    case refuse(Refusal)
  }

  public let minimumInterval: TimeInterval
  public let budget: Int
  public let window: TimeInterval
  private var granted: [Date] = []

  public init(minimumInterval: TimeInterval = 60, budget: Int = 3, window: TimeInterval = 1_800) {
    self.minimumInterval = minimumInterval
    self.budget = budget
    self.window = window
  }

  /// `idle` is nil when the helper could not prove either way. A granted
  /// decision is recorded: the caller must then really restart.
  public mutating func request(now: Date, idle: Bool?) -> Decision {
    granted.removeAll { now.timeIntervalSince($0) >= window || $0 > now }
    guard let idle else { return .refuse(.idleUnknown) }
    guard idle else { return .refuse(.notIdle) }
    if let last = granted.last, now.timeIntervalSince(last) < minimumInterval {
      return .refuse(.tooSoon)
    }
    guard granted.count < budget else { return .refuse(.budgetExhausted) }
    granted.append(now)
    return .allow
  }
}

/// Notices that the Mac slept: the sleep-excluding clock falls behind the
/// sleep-including one. Used only to write a "wake" line into the log, so a
/// later failure can be correlated with it.
public struct NativeWakeDetector: Sendable {
  public let threshold: TimeInterval
  private var last: (uptime: UInt64, continuous: UInt64)?

  public init(threshold: TimeInterval = 20) { self.threshold = threshold }

  /// Both clocks in nanoseconds. Returns the slept duration when above threshold.
  public mutating func observe(uptimeNanoseconds: UInt64, continuousNanoseconds: UInt64)
    -> TimeInterval?
  {
    defer { last = (uptimeNanoseconds, continuousNanoseconds) }
    guard let last, uptimeNanoseconds >= last.uptime, continuousNanoseconds >= last.continuous
    else { return nil }
    let awake = Double(uptimeNanoseconds - last.uptime)
    let elapsed = Double(continuousNanoseconds - last.continuous)
    let slept = (elapsed - awake) / 1e9
    return slept >= threshold ? slept : nil
  }
}
