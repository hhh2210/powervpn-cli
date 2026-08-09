import Darwin
import Dispatch
import Foundation
import PowerVPNPortal

enum PortalLoginCommandError: Error, Equatable, CustomStringConvertible {
  case invalidArguments

  var description: String { "usage: powervpn login" }
}

struct PortalLoginCommandResult: Equatable, Sendable {
  let standardOutput: String
  let exitCode: Int32
}

typealias PortalLoginRuntimeOperation = @Sendable () async -> PortalLoginReport
typealias PortalLoginSignalMonitorFactory = @Sendable () -> any PortalLoginSignalMonitoring

protocol PortalLoginSignalMonitoring: AnyObject, Sendable {
  func start(handler: @escaping @Sendable () -> Void)
  func stop()
}

func runPortalLoginCommand(
  _ arguments: [String],
  runtime: @escaping PortalLoginRuntimeOperation = {
    await PortalLoginRuntime.runCurrentMachine()
  },
  signalMonitorFactory: PortalLoginSignalMonitorFactory = {
    DarwinPortalLoginSignalMonitor()
  }
) async throws -> PortalLoginCommandResult {
  guard arguments == ["login"] else {
    throw PortalLoginCommandError.invalidArguments
  }

  let cancellation = PortalLoginTaskCancellation()
  let signalMonitor = signalMonitorFactory()
  signalMonitor.start { cancellation.request() }
  let task = Task { await runtime() }
  cancellation.install(task)
  let report = await task.value
  cancellation.clear()
  signalMonitor.stop()

  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  let data = try encoder.encode(report)
  return PortalLoginCommandResult(
    standardOutput: String(decoding: data, as: UTF8.self),
    exitCode: report.transactionAccepted ? 0 : 2
  )
}

private final class PortalLoginTaskCancellation: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<PortalLoginReport, Never>?
  private var requested = false

  func install(_ task: Task<PortalLoginReport, Never>) {
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

private final class DarwinPortalLoginSignalMonitor: PortalLoginSignalMonitoring,
  @unchecked Sendable
{
  private let lock = NSLock()
  private let queue = DispatchQueue(label: "org.powervpn.cli.portal-login-signals")
  private var sources: [DispatchSourceSignal] = []
  private var previousHandlers: [(signal: Int32, handler: sig_t?)] = []

  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock {
      guard sources.isEmpty else { return }
      for number in [SIGINT, SIGTERM] {
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

  deinit {
    stop()
  }
}
