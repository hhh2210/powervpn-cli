import Darwin
import Foundation

/// One process, pinned by its pid, owner, the path it was executed as and its
/// start time, so a later check never mistakes a reused pid for it.
///
/// The executed path comes from KERN_PROCARGS2: it is what was passed to exec,
/// unlike argv[0] (which `ps -o comm` shows and any caller can set), and it
/// stays the same after the file is replaced, unlike proc_pidpath.
package struct ProcessIdentity: Equatable, Sendable {
  package let pid: pid_t
  package let uid: uid_t
  package let executedPath: String
  package let startMicroseconds: UInt64

  package enum Lookup: Equatable, Sendable {
    case running(ProcessIdentity)
    /// No live process has this pid: it exited, or is a zombie awaiting its parent.
    case gone
    /// The process could not be inspected, so nothing is known about it.
    case unknown
  }

  package static func lookup(_ pid: pid_t) -> Lookup {
    guard pid > 0 else { return .gone }
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else {
      return errno == ESRCH ? .gone : .unknown
    }
    if info.pbi_status == UInt32(SZOMB) { return .gone }
    guard let path = executedPath(pid) else {
      // It may have exited between the two queries.
      var again = proc_bsdinfo()
      guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &again, size) == size else {
        return errno == ESRCH ? .gone : .unknown
      }
      return again.pbi_status == UInt32(SZOMB) ? .gone : .unknown
    }
    return .running(
      ProcessIdentity(
        pid: pid, uid: info.pbi_uid, executedPath: path,
        startMicroseconds: info.pbi_start_tvsec &* 1_000_000 &+ info.pbi_start_tvusec))
  }

  /// Whether the pid still names this process; nil when that cannot be told.
  package var isRunning: Bool? {
    switch Self.lookup(pid) {
    case .running(let now): now == self
    case .gone: false
    case .unknown: nil
    }
  }

  /// SIGTERM, then SIGKILL once `grace` has passed. The identity is checked
  /// right before each signal, so a pid reused meanwhile is left alone (macOS
  /// has no process handle to close the remaining check-to-kill window).
  /// True only once this process is confirmed gone; false if it still runs
  /// or could no longer be inspected.
  package func stop(grace: TimeInterval = 5) -> Bool {
    let polls = max(1, Int(grace * 10))
    for signal in [SIGTERM, SIGKILL] {
      guard let running = isRunning else { return false }
      if !running { return true }
      _ = kill(pid, signal)
      for _ in 0..<polls where isRunning == true { usleep(100_000) }
    }
    return isRunning == false
  }

  private static func executedPath(_ pid: pid_t) -> String? {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else {
      return nil
    }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else {
      return nil
    }
    // argc, then the executed path, NUL-terminated.
    let path = buffer[MemoryLayout<Int32>.size..<size].prefix { $0 != 0 }
    return path.isEmpty ? nil : String(decoding: path, as: UTF8.self)
  }
}
