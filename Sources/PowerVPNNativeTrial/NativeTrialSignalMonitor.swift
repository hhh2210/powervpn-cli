import Darwin
import Dispatch
import Foundation
import PowerVPNCore

final class NativeTrialCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<Void, Never>?
  private var cancelled = false
  private var interruption: VICIInterruptHandle?
  func attach(_ task: Task<Void, Never>) {
    let wasCancelled = lock.withLock {
      self.task = task
      return cancelled
    }
    if wasCancelled { task.cancel() }
  }
  func cancel() {
    let active = lock.withLock {
      cancelled = true
      return (task, interruption)
    }
    active.0?.cancel()
    active.1?.interrupt()
  }
  func attachInterruption(_ handle: VICIInterruptHandle) {
    let wasCancelled = lock.withLock {
      interruption = handle
      return cancelled
    }
    if wasCancelled { handle.interrupt() }
  }
}

final class NativeTrialSignalMonitor {
  private var sources: [DispatchSourceSignal] = []
  init(cancellation: NativeTrialCancellation) {
    for number in [SIGINT, SIGTERM, SIGHUP] {
      signal(number, SIG_IGN)
      let source = DispatchSource.makeSignalSource(signal: number, queue: .global(qos: .utility))
      source.setEventHandler { cancellation.cancel() }
      source.resume()
      sources.append(source)
    }
  }
  deinit { for source in sources { source.cancel() } }
}
