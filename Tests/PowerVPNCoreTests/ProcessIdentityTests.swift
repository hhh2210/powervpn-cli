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
      if case .running(let identity) = ProcessIdentity.lookup(process.processIdentifier),
        identity.executedPath == path
      {
        return identity
      }
      usleep(20_000)
    }
    guard case .running(let identity) = ProcessIdentity.lookup(process.processIdentifier) else {
      Issue.record("pid \(process.processIdentifier) is not running")
      throw CancellationError()
    }
    return identity
  }

  @Test func identifiesAChildAndStopsItWithSIGTERM() throws {
    let child = try run("/bin/sleep", ["30"])
    defer { if child.isRunning { kill(child.processIdentifier, SIGKILL) } }
    let identity = try identity(of: child, executed: "/bin/sleep")
    #expect(identity.executedPath == "/bin/sleep")
    #expect(identity.uid == getuid())
    #expect(identity.isRunning == true)

    #expect(identity.stop(grace: 2))
    child.waitUntilExit()
    #expect(child.terminationReason == .uncaughtSignal)
    #expect(child.terminationStatus == SIGTERM)
    #expect(identity.isRunning == false)
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
      #expect(impostor.isRunning == false)
      #expect(impostor.stop(grace: 0.1))
    }
    #expect(child.isRunning)
    #expect(real.isRunning == true)
  }

  @Test func reportsAnExitedPidAsGone() throws {
    let child = try run("/usr/bin/true", [])
    child.waitUntilExit()
    #expect(ProcessIdentity.lookup(child.processIdentifier) == .gone)
    #expect(ProcessIdentity.lookup(0) == .gone)
    #expect(ProcessIdentity.lookup(-1) == .gone)
  }

  /// A process this caller may not inspect is unknown, never gone, so stop()
  /// does not report success for it.
  @Test(.enabled(if: geteuid() != 0)) func cannotInspectAnotherUsersProcess() throws {
    #expect(ProcessIdentity.lookup(1) == .unknown)
    let launchd = ProcessIdentity(
      pid: 1, uid: 0, executedPath: "/sbin/launchd", startMicroseconds: 0)
    #expect(launchd.isRunning == nil)
    #expect(!launchd.stop(grace: 0.1))
  }
}
