import Darwin
import Dispatch
import Foundation

typealias CLISignalMonitorFactory = @Sendable () -> any CLISignalMonitoring

protocol CLISignalMonitoring: AnyObject, Sendable {
  func start(handler: @escaping @Sendable () -> Void)
  func stop()
}

final class CLITaskCancellation<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<Value, Never>?
  private var requested = false

  func install(_ task: Task<Value, Never>) {
    let cancelImmediately = lock.withLock {
      self.task = task
      return requested
    }
    if cancelImmediately { task.cancel() }
  }

  func request() {
    let installed = lock.withLock {
      requested = true
      return task
    }
    installed?.cancel()
  }

  func clear() {
    lock.withLock { task = nil }
  }
}

actor CLITaskStartGate {
  private var opened = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    guard !opened else { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func open() {
    guard !opened else { return }
    opened = true
    let pending = waiters
    waiters.removeAll()
    for continuation in pending { continuation.resume() }
  }
}

final class DarwinCLISignalMonitor: CLISignalMonitoring, @unchecked Sendable {
  private let lock = NSLock()
  private let queue = DispatchQueue(label: "org.powervpn.cli.signals")
  private var sources: [DispatchSourceSignal] = []
  private var previousHandlers: [(signal: Int32, handler: sig_t?)] = []

  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock {
      guard sources.isEmpty else { return }
      for number in [SIGHUP, SIGINT, SIGTERM] {
        let previous = Darwin.signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
        source.setEventHandler(handler: handler)
        previousHandlers.append((number, previous))
        sources.append(source)
        source.resume()
      }
    }
  }

  func stop() {
    let saved = lock.withLock {
      let saved = (sources, previousHandlers)
      sources.removeAll()
      previousHandlers.removeAll()
      return saved
    }
    for source in saved.0 { source.cancel() }
    queue.sync {}
    for disposition in saved.1 {
      Darwin.signal(disposition.signal, disposition.handler)
    }
  }

  deinit { stop() }
}
