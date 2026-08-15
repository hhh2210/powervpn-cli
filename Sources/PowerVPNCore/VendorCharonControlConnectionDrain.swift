import Dispatch

typealias VendorCharonConnectionDrainScheduler =
  @Sendable (
    _ queue: DispatchQueue,
    _ expiration: @escaping @Sendable () -> Void
  ) -> @Sendable () -> Void

/// Retains a stopped helper connection briefly so its asynchronous teardown
/// notification can leave on the same GLOBAL remote connection as the request.
/// The cycle through the one-shot timer is intentional: emergency-stop has no
/// lease object to own the drain after its receipt returns.
final class VendorCharonControlConnectionDrain: @unchecked Sendable {
  static let productionDurationMilliseconds = 10_000

  static func productionScheduler(
    _ queue: DispatchQueue,
    _ expiration: @escaping @Sendable () -> Void
  ) -> @Sendable () -> Void {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(
      deadline: .now() + .milliseconds(productionDurationMilliseconds)
    )
    timer.setEventHandler(handler: expiration)
    timer.resume()
    return {
      timer.setEventHandler {}
      timer.cancel()
    }
  }

  private let scheduler: VendorCharonConnectionDrainScheduler
  private var cancelDriver: (@Sendable () -> Void)?
  private var cancelExpiration: (@Sendable () -> Void)?
  private var armed = false

  init(
    cancelDriver: @escaping @Sendable () -> Void,
    scheduler: @escaping VendorCharonConnectionDrainScheduler
  ) {
    self.cancelDriver = cancelDriver
    self.scheduler = scheduler
  }

  func arm(on queue: DispatchQueue) {
    guard !armed else { return }
    armed = true
    cancelExpiration = scheduler(queue) { [self] in
      _ = cancelNow()
    }
  }

  @discardableResult
  func cancelNow() -> Bool {
    let cancelExpiration = cancelExpiration
    self.cancelExpiration = nil
    cancelExpiration?()
    guard let cancelDriver else { return false }
    self.cancelDriver = nil
    cancelDriver()
    return true
  }
}
