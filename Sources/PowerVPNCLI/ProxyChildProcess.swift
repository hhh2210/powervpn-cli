import Darwin
import Foundation

enum ProxyChildInput: Equatable, Sendable {
  case inherited
  case null
}

enum ProxyChildOutput: Equatable, Sendable {
  case inherited
  case null
}

struct ProxyChildSpecification: Equatable, Sendable {
  let executable: String
  let arguments: [String]
  let standardInput: ProxyChildInput
  let standardOutput: ProxyChildOutput
}

enum ProxyChildReadiness: Equatable, Sendable {
  case none
  case loopback(port: UInt16, timeoutMilliseconds: Int)
}

enum ProxyChildRunOutcome: Equatable, Sendable {
  case exited(Int32)
  case spawnFailed
  case readinessFailed
  case cancelled
}

struct ProxyChildRunResult: Equatable, Sendable {
  let outcome: ProxyChildRunOutcome
  let becameReady: Bool
}

protocol ProxyChildRunning: Sendable {
  func run(
    _ specification: ProxyChildSpecification,
    readiness: ProxyChildReadiness,
    onReady: @escaping @Sendable () -> Void
  ) async -> ProxyChildRunResult
}

struct FoundationProxyChildRunner: ProxyChildRunning {
  func run(
    _ specification: ProxyChildSpecification,
    readiness: ProxyChildReadiness,
    onReady: @escaping @Sendable () -> Void
  ) async -> ProxyChildRunResult {
    let context = ProxyChildContext(process: Self.makeProcess(specification))
    context.process.terminationHandler = { process in
      context.termination.resolve(process.terminationStatus)
    }
    let occupiedBeforeLaunch: Bool
    if case .loopback(let port, _) = readiness {
      occupiedBeforeLaunch = Self.loopbackAccepts(port)
    } else {
      occupiedBeforeLaunch = false
    }

    return await withTaskCancellationHandler {
      await launchAndWait(
        context: context,
        readiness: readiness,
        occupiedBeforeLaunch: occupiedBeforeLaunch,
        onReady: onReady
      )
    } onCancel: {
      context.lifecycle.cancel()
    }
  }

  private func launchAndWait(
    context: ProxyChildContext,
    readiness: ProxyChildReadiness,
    occupiedBeforeLaunch: Bool,
    onReady: @escaping @Sendable () -> Void
  ) async -> ProxyChildRunResult {
    guard !Task.isCancelled, context.lifecycle.prepareToLaunch() else {
      return ProxyChildRunResult(outcome: .cancelled, becameReady: false)
    }
    do {
      try context.process.run()
    } catch {
      context.lifecycle.launchFailed()
      return ProxyChildRunResult(outcome: .spawnFailed, becameReady: false)
    }
    context.lifecycle.didLaunch()
    switch readiness {
    case .none:
      let status = await context.termination.value()
      return ProxyChildRunResult(
        outcome: context.lifecycle.wasCancelled ? .cancelled : .exited(Self.exitCode(status)),
        becameReady: false
      )
    case .loopback(let port, let timeoutMilliseconds):
      return await waitForLoopback(
        port: port,
        timeoutMilliseconds: timeoutMilliseconds,
        occupiedBeforeLaunch: occupiedBeforeLaunch,
        context: context,
        onReady: onReady
      )
    }
  }

  private func waitForLoopback(
    port: UInt16,
    timeoutMilliseconds: Int,
    occupiedBeforeLaunch: Bool,
    context: ProxyChildContext,
    onReady: @escaping @Sendable () -> Void
  ) async -> ProxyChildRunResult {
    let deadline = ContinuousClock.now + .milliseconds(timeoutMilliseconds)
    while ContinuousClock.now < deadline {
      if context.lifecycle.wasCancelled || Task.isCancelled {
        context.lifecycle.cancel()
        _ = await context.termination.value()
        return ProxyChildRunResult(outcome: .cancelled, becameReady: false)
      }
      if !context.process.isRunning {
        let status = await context.termination.value()
        return ProxyChildRunResult(
          outcome: .exited(Self.exitCode(status)),
          becameReady: false
        )
      }
      if !occupiedBeforeLaunch && Self.loopbackAccepts(port) {
        onReady()
        let status = await context.termination.value()
        return ProxyChildRunResult(
          outcome: context.lifecycle.wasCancelled ? .cancelled : .exited(Self.exitCode(status)),
          becameReady: true
        )
      }
      try? await Task.sleep(for: .milliseconds(25))
    }
    context.lifecycle.terminate()
    _ = await context.termination.value()
    return ProxyChildRunResult(outcome: .readinessFailed, becameReady: false)
  }

  private static func makeProcess(_ specification: ProxyChildSpecification) -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: specification.executable)
    process.arguments = specification.arguments
    process.standardInput =
      specification.standardInput == .inherited
      ? FileHandle.standardInput : FileHandle(forReadingAtPath: "/dev/null")
    process.standardOutput =
      specification.standardOutput == .inherited
      ? FileHandle.standardOutput : FileHandle(forWritingAtPath: "/dev/null")
    process.standardError = FileHandle.standardError
    return process
  }

  private static func exitCode(_ status: Int32) -> Int32 {
    min(255, max(0, status))
  }

  private static func loopbackAccepts(_ port: UInt16) -> Bool {
    let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { return false }
    defer { Darwin.close(descriptor) }

    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    return withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(
          descriptor,
          $0,
          socklen_t(MemoryLayout<sockaddr_in>.size)
        ) == 0
      }
    }
  }
}
private final class ProxyChildContext: @unchecked Sendable {
  let process: Process
  let lifecycle: ProxyChildLifecycle
  let termination = ProxyChildTermination()

  init(process: Process) {
    self.process = process
    lifecycle = ProxyChildLifecycle(process: process)
  }
}

private final class ProxyChildLifecycle: @unchecked Sendable {
  private let lock = NSLock()
  private let process: Process
  private var cancellationRequested = false
  private var launched = false
  private var launchInProgress = false

  init(process: Process) {
    self.process = process
  }

  var wasCancelled: Bool {
    lock.withLock { cancellationRequested }
  }

  func prepareToLaunch() -> Bool {
    lock.withLock {
      guard !cancellationRequested else { return false }
      launchInProgress = true
      return true
    }
  }

  func didLaunch() {
    let shouldTerminate = lock.withLock {
      launchInProgress = false
      launched = true
      return cancellationRequested
    }
    if shouldTerminate { process.terminate() }
  }

  func launchFailed() {
    lock.withLock { launchInProgress = false }
  }

  func cancel() {
    let shouldTerminate = lock.withLock {
      cancellationRequested = true
      return launched
    }
    if shouldTerminate { process.terminate() }
  }

  func terminate() {
    let shouldTerminate = lock.withLock { launched }
    if shouldTerminate { process.terminate() }
  }
}

private final class ProxyChildTermination: @unchecked Sendable {
  private let lock = NSLock()
  private var status: Int32?
  private var continuation: CheckedContinuation<Int32, Never>?

  func resolve(_ status: Int32) {
    let continuation = lock.withLock {
      guard self.status == nil else { return nil as CheckedContinuation<Int32, Never>? }
      self.status = status
      let continuation = self.continuation
      self.continuation = nil
      return continuation
    }
    continuation?.resume(returning: status)
  }

  func value() async -> Int32 {
    await withCheckedContinuation { continuation in
      let resolved = lock.withLock { () -> Int32? in
        if let status { return status }
        self.continuation = continuation
        return nil
      }
      if let resolved { continuation.resume(returning: resolved) }
    }
  }
}
