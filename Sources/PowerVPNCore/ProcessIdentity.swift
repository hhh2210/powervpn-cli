import Darwin
import Foundation

/// One process, pinned by its pid, owner, the path it was executed as and its
/// start time, so a later check never mistakes a reused pid for it.
///
/// The executed path comes from KERN_PROCARGS2: it stays what was passed to
/// exec even after the file is replaced, unlike proc_pidpath.
package struct ProcessIdentity: Equatable, Sendable {
  package let pid: pid_t
  package let uid: uid_t
  package let executedPath: String
  package let startMicroseconds: UInt64

  /// nil unless `pid` is a live, non-zombie process this caller may inspect.
  package static func current(_ pid: pid_t) -> ProcessIdentity? {
    guard pid > 0 else { return nil }
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
      info.pbi_status != UInt32(SZOMB),
      let path = executedPath(pid)
    else { return nil }
    return ProcessIdentity(
      pid: pid, uid: info.pbi_uid, executedPath: path,
      startMicroseconds: info.pbi_start_tvsec &* 1_000_000 &+ info.pbi_start_tvusec)
  }

  package var isRunning: Bool { Self.current(pid) == self }

  /// SIGTERM, then SIGKILL once `grace` has passed. The identity is checked
  /// right before each signal, so a pid reused meanwhile is left alone (macOS
  /// has no process handle to close the remaining check-to-kill window).
  /// True once this process is gone.
  package func stop(grace: TimeInterval = 5) -> Bool {
    let polls = max(1, Int(grace * 10))
    for signal in [SIGTERM, SIGKILL] {
      guard isRunning else { return true }
      _ = kill(pid, signal)
      for _ in 0..<polls where isRunning { usleep(100_000) }
    }
    return !isRunning
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
