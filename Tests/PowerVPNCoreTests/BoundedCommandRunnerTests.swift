import Foundation
import Testing

@testable import PowerVPNCore

@Suite(.serialized) struct BoundedCommandRunnerTests {
  @Test func fastExitAlwaysPublishesStartedAndReaped() async {
    for _ in 0..<64 {
      let result = await BoundedCommandRunner().run(
        request("/usr/bin/true", timeout: 1_000)
      )
      #expect(result.succeeded)
      #expect(result.started)
      #expect(result.exitStatus == 0)
      #expect(result.reaped)
    }
  }

  @Test func firstOversizedStdoutChunkCannotBypassCap() async {
    let marker = String(repeating: "x", count: 513)
    let result = await BoundedCommandRunner().run(
      request(
        "/usr/bin/printf",
        arguments: ["%s", marker],
        stdoutLimit: 512
      )
    )
    #expect(result.outcome == .stdoutLimitExceeded)
    #expect(result.started)
    #expect(result.stdout.isEmpty)
    #expect(result.stderr.isEmpty)
    #expect(result.reaped)
  }

  @Test func firstOversizedStderrChunkCannotBypassCap() async {
    let program = "BEGIN { for (i=0;i<513;i++) printf \"x\" > \"/dev/stderr\" }"
    let result = await BoundedCommandRunner().run(
      request(
        "/usr/bin/awk",
        arguments: [program],
        stderrLimit: 512
      )
    )
    #expect(result.outcome == .stderrLimitExceeded)
    #expect(result.started)
    #expect(result.stdout.isEmpty)
    #expect(result.stderr.isEmpty)
    #expect(result.reaped)
  }

  @Test func unboundedProducerIsStoppedByCapBeforeTimeout() async {
    for _ in 0..<32 {
      let clock = ContinuousClock()
      let start = clock.now
      let result = await BoundedCommandRunner().run(
        request("/usr/bin/yes", timeout: 1_000, stdoutLimit: 128)
      )
      #expect(result.outcome == .stdoutLimitExceeded)
      #expect(result.terminationRequested)
      #expect(result.reaped)
      #expect(start.duration(to: clock.now) < .milliseconds(500))
    }
  }

  @Test func timeoutIsAbsoluteAndFailureOutputIsValueFree() async {
    let result = await BoundedCommandRunner().run(
      request("/bin/sleep", arguments: ["1"], timeout: 1)
    )
    #expect(result.outcome == .timedOut)
    #expect(result.started)
    #expect(result.terminationRequested)
    #expect(result.stdout.isEmpty)
    #expect(result.stderr.isEmpty)
    #expect(result.reaped)
  }

  @Test func taskCancellationTerminatesAndReaps() async {
    let task = Task {
      await BoundedCommandRunner().run(
        request("/bin/sleep", arguments: ["1"], timeout: 5_000)
      )
    }
    try? await Task.sleep(for: .milliseconds(10))
    task.cancel()
    let result = await task.value
    #expect(result.outcome == .cancelled)
    #expect(result.started)
    #expect(result.terminationRequested)
    #expect(result.reaped)
  }

  @Test func invalidShellAndNonzeroExitNeverExposeRawOutput() async {
    let shell = await BoundedCommandRunner().run(request("/bin/sh"))
    #expect(shell.outcome == .invalidRequest)
    #expect(!shell.started)
    let disguisedShell = await BoundedCommandRunner().run(request("/tmp/sh"))
    #expect(disguisedShell.outcome == .invalidRequest)
    let traversal = await BoundedCommandRunner().run(request("/usr/bin/../bin/true"))
    #expect(traversal.outcome == .invalidRequest)

    let marker = "sensitive-nonzero-marker"
    let failed = await BoundedCommandRunner().run(
      request("/bin/ls", arguments: ["/definitely-missing-\(marker)"])
    )
    #expect(failed.outcome == .exited)
    #expect(failed.exitStatus != 0)
    #expect(failed.stdout.isEmpty)
    #expect(failed.stderr.isEmpty)
    #expect(!String(describing: failed).contains(marker))
  }
}

private func request(
  _ executable: String,
  arguments: [String] = [],
  timeout: Int = 1_000,
  stdoutLimit: Int = 1_024,
  stderrLimit: Int = 1_024
) -> BoundedCommandRequest {
  BoundedCommandRequest(
    executable: executable,
    arguments: arguments,
    timeoutMilliseconds: timeout,
    stdoutLimitBytes: stdoutLimit,
    stderrLimitBytes: stderrLimit
  )
}
