import Darwin
import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct ProcessIdentityTests {
  private func run(_ executable: String, _ arguments: [String]) throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    try process.run()
    return process
  }

  /// The identity once the child has exec'd `path` (a shell may still be
  /// running when `run` returns).
  private func identity(of process: Process, executed path: String) throws -> ProcessIdentity {
    for _ in 0..<50 {
      if let identity = ProcessIdentity.current(process.processIdentifier),
        identity.executedPath == path
      {
        return identity
      }
      usleep(20_000)
    }
    return try #require(ProcessIdentity.current(process.processIdentifier))
  }

  @Test func identifiesAChildAndStopsItWithSIGTERM() throws {
    let child = try run("/bin/sleep", ["30"])
    defer { if child.isRunning { kill(child.processIdentifier, SIGKILL) } }
    let identity = try identity(of: child, executed: "/bin/sleep")
    #expect(identity.executedPath == "/bin/sleep")
    #expect(identity.uid == getuid())
    #expect(identity.isRunning)

    #expect(identity.stop(grace: 2))
    child.waitUntilExit()
    #expect(child.terminationReason == .uncaughtSignal)
    #expect(child.terminationStatus == SIGTERM)
    #expect(!identity.isRunning)
  }

  @Test func escalatesToSIGKILLWhenSIGTERMIsIgnored() throws {
    // An ignored signal stays ignored across exec.
    let child = try run("/bin/sh", ["-c", "trap '' TERM; exec /bin/sleep 30"])
    defer { if child.isRunning { kill(child.processIdentifier, SIGKILL) } }
    let identity = try identity(of: child, executed: "/bin/sleep")
    #expect(identity.executedPath == "/bin/sleep")

    #expect(identity.stop(grace: 0.3))
    child.waitUntilExit()
    #expect(child.terminationStatus == SIGKILL)
  }

  @Test func neverSignalsAProcessThatOnlySharesThePid() throws {
    let child = try run("/bin/sleep", ["30"])
    defer {
      kill(child.processIdentifier, SIGKILL)
      child.waitUntilExit()
    }
    let real = try identity(of: child, executed: "/bin/sleep")
    let impostors = [
      ProcessIdentity(
        pid: real.pid, uid: real.uid, executedPath: real.executedPath,
        startMicroseconds: real.startMicroseconds + 1),
      ProcessIdentity(
        pid: real.pid, uid: real.uid, executedPath: "/usr/sbin/charon",
        startMicroseconds: real.startMicroseconds),
    ]
    for impostor in impostors {
      #expect(!impostor.isRunning)
      #expect(impostor.stop(grace: 0.1))
    }
    #expect(child.isRunning)
    #expect(real.isRunning)
  }

  @Test func rejectsPidsThatNameNoProcess() {
    #expect(ProcessIdentity.current(0) == nil)
    #expect(ProcessIdentity.current(-1) == nil)
  }
}
