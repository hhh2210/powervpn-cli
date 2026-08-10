import Foundation

final class StickyConnectionLifecycle<Resource, Event>: @unchecked Sendable {
  typealias Handler = @Sendable (Event) -> Void

  private enum Phase {
    case idle
    case constructing
    case active(Resource)
    case cancelled
  }

  private let lock = NSLock()
  private var phase = Phase.idle
  private var handler: Handler?

  func begin(_ handler: @escaping Handler) -> Bool {
    lock.withLock {
      guard case .idle = phase else { return false }
      phase = .constructing
      self.handler = handler
      return true
    }
  }

  func publishAndStart(
    _ resource: Resource,
    start: (Resource) -> Void
  ) -> Bool {
    lock.lock()
    guard case .constructing = phase else {
      lock.unlock()
      return false
    }
    phase = .active(resource)
    // The start call is intentionally inside the lifecycle lock. Its
    // production implementation only schedules Network.framework work, so a
    // concurrent cancel either precedes publication or follows start exactly.
    start(resource)
    lock.unlock()
    return true
  }

  func cancel() -> Resource? {
    lock.withLock {
      handler = nil
      switch phase {
      case .idle, .constructing:
        phase = .cancelled
        return nil
      case .active(let resource):
        phase = .cancelled
        return resource
      case .cancelled:
        return nil
      }
    }
  }

  var acceptsCallbacks: Bool {
    lock.withLock {
      guard handler != nil else { return false }
      guard case .active = phase else { return false }
      return true
    }
  }

  func takeHandler() -> Handler? {
    lock.withLock {
      guard handler != nil else { return nil }
      switch phase {
      case .constructing, .active:
        let retained = handler
        handler = nil
        return retained
      case .idle, .cancelled:
        return nil
      }
    }
  }
}
