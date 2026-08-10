import Darwin
import Foundation

final class BoundedCommandExecution: @unchecked Sendable {
  private enum Stream { case stdout, stderr }

  private let request: BoundedCommandRequest
  private let process = Process()
  private let stdoutPipe = Pipe()
  private let stderrPipe = Pipe()
  private let lock = NSLock()
  private var stdout = Data()
  private var stderr = Data()
  private var stdoutClosed = false
  private var stderrClosed = false
  private var launchResolved = false
  private var started = false
  private var terminated = false
  private var exitStatus: Int32?
  private var overrideOutcome: BoundedCommandOutcome?
  private var terminationRequested = false
  private var killRequested = false
  private var timer: DispatchSourceTimer?
  private var continuation: CheckedContinuation<BoundedCommandResult, Never>?
  private var completed: BoundedCommandResult?

  init(request: BoundedCommandRequest) {
    self.request = request
  }

  func start() {
    configureProcess()
    stdoutPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
      self?.receive(handle.availableData, from: .stdout)
    }
    stderrPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
      self?.receive(handle.availableData, from: .stderr)
    }
    process.terminationHandler = { [weak self] process in
      self?.processTerminated(status: process.terminationStatus)
    }
    do {
      try process.run()
      let source = makeTimer()
      let terminateAfterStart = lock.withLock { () -> Bool in
        started = true
        timer = source
        let shouldTerminate = overrideOutcome != nil && !terminated
        if shouldTerminate { terminationRequested = true }
        return shouldTerminate
      }
      source.resume()
      if terminateAfterStart { terminateRunningProcess() }
      let publication = lock.withLock { () -> Publication? in
        launchResolved = true
        return publicationIfReady()
      }
      publication?.resume()
    } catch {
      stdoutPipe.fileHandleForReading.readabilityHandler = nil
      stderrPipe.fileHandleForReading.readabilityHandler = nil
      publishImmediate(.launchFailed)
    }
  }

  func result() async -> BoundedCommandResult {
    await withCheckedContinuation { continuation in
      let immediate = lock.withLock { () -> BoundedCommandResult? in
        if let completed { return completed }
        self.continuation = continuation
        return nil
      }
      if let immediate { continuation.resume(returning: immediate) }
    }
  }

  func cancel() {
    requestTermination(.cancelled)
  }

  private func configureProcess() {
    process.executableURL = URL(fileURLWithPath: request.executable)
    process.arguments = request.arguments
    process.environment = ["LANG": "C", "LC_ALL": "C"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe
  }

  private func makeTimer() -> DispatchSourceTimer {
    let source = DispatchSource.makeTimerSource()
    source.schedule(deadline: .now() + .milliseconds(request.timeoutMilliseconds))
    source.setEventHandler { [weak self] in self?.requestTermination(.timedOut) }
    return source
  }

  private func receive(_ data: Data, from stream: Stream) {
    if data.isEmpty {
      if stream == .stdout {
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
      } else {
        stderrPipe.fileHandleForReading.readabilityHandler = nil
      }
      let publication = lock.withLock { () -> Publication? in
        if stream == .stdout { stdoutClosed = true } else { stderrClosed = true }
        return publicationIfReady()
      }
      publication?.resume()
      return
    }

    let exceeded = lock.withLock { () -> (outcome: BoundedCommandOutcome, terminate: Bool)? in
      guard completed == nil, overrideOutcome == nil else { return nil }
      if stream == .stdout {
        guard stdout.count <= request.stdoutLimitBytes,
          data.count <= request.stdoutLimitBytes - stdout.count
        else {
          return recordLimitExceeded(.stdoutLimitExceeded)
        }
        stdout.append(data)
      } else {
        guard stderr.count <= request.stderrLimitBytes,
          data.count <= request.stderrLimitBytes - stderr.count
        else {
          return recordLimitExceeded(.stderrLimitExceeded)
        }
        stderr.append(data)
      }
      return nil
    }
    if exceeded?.terminate == true { terminateRunningProcess() }
  }

  private func processTerminated(status: Int32) {
    let publication = lock.withLock { () -> Publication? in
      terminated = true
      exitStatus = status
      return publicationIfReady()
    }
    publication?.resume()
  }

  private func requestTermination(_ outcome: BoundedCommandOutcome) {
    let shouldTerminate = lock.withLock { () -> Bool in
      guard completed == nil, overrideOutcome == nil, started else { return false }
      guard !terminated else { return false }
      overrideOutcome = outcome
      terminationRequested = true
      return true
    }
    guard shouldTerminate else { return }
    terminateRunningProcess()
  }

  /// Called only while `lock` is held, making the cap outcome precede any EOF
  /// publication from another readability callback.
  private func recordLimitExceeded(
    _ outcome: BoundedCommandOutcome
  ) -> (outcome: BoundedCommandOutcome, terminate: Bool) {
    overrideOutcome = outcome
    let shouldTerminate = started && !terminated
    if shouldTerminate { terminationRequested = true }
    return (outcome, shouldTerminate)
  }

  private func terminateRunningProcess() {
    process.terminate()
    DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self] in
      self?.forceKillIfNeeded()
    }
  }

  private func forceKillIfNeeded() {
    let pid = lock.withLock { () -> pid_t? in
      guard started, !terminated, completed == nil, process.isRunning else { return nil }
      killRequested = true
      return process.processIdentifier
    }
    if let pid { _ = Darwin.kill(pid, SIGKILL) }
  }

  private func publishImmediate(_ outcome: BoundedCommandOutcome) {
    let result = BoundedCommandResult.immediate(outcome)
    let continuation = lock.withLock { () -> CheckedContinuation<BoundedCommandResult, Never>? in
      completed = result
      let value = self.continuation
      self.continuation = nil
      return value
    }
    continuation?.resume(returning: result)
  }

  private func publicationIfReady() -> Publication? {
    guard completed == nil, launchResolved, terminated, stdoutClosed, stderrClosed else {
      return nil
    }
    timer?.cancel()
    timer = nil
    let outcome = overrideOutcome ?? .exited
    let exposeOutput = outcome == .exited && exitStatus == 0
    let result = BoundedCommandResult(
      outcome: outcome,
      started: started,
      exitStatus: exitStatus,
      stdout: exposeOutput ? stdout : Data(),
      stderr: exposeOutput ? stderr : Data(),
      terminationRequested: terminationRequested,
      killRequested: killRequested,
      reaped: true
    )
    stdout.removeAll(keepingCapacity: false)
    stderr.removeAll(keepingCapacity: false)
    completed = result
    let value = continuation
    continuation = nil
    return Publication(continuation: value, result: result)
  }
}

private struct Publication: Sendable {
  let continuation: CheckedContinuation<BoundedCommandResult, Never>?
  let result: BoundedCommandResult

  func resume() {
    continuation?.resume(returning: result)
  }
}
