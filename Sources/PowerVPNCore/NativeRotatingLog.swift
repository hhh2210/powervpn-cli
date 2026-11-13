import Darwin
import Foundation

/// Size-rotated, append-only text log. The root helper writes one (0600, in a
/// root-only directory) and the CLI writes one for per-attempt timings (0600,
/// in the user's state directory).
///
/// It reopens by path when the file was unlinked or replaced while the writer
/// ran (a removed log must not leave the daemon writing to a deleted inode),
/// never follows a symlink, and keeps at most `keep` rotated files, so the disk
/// cost is bounded by `maximumBytes * (keep + 1)`. Lines are written as given:
/// callers sanitize first (NativeLogSanitizer).
public final class NativeRotatingLog: @unchecked Sendable {
  public let path: String
  public let maximumBytes: Int
  public let keep: Int
  private let lock = NSLock()
  private var descriptor: Int32 = -1
  private var device: dev_t = 0
  private var inode: ino_t = 0
  private var size = 0

  public init(path: String, maximumBytes: Int = 1_048_576, keep: Int = 4) {
    self.path = path
    self.maximumBytes = max(1_024, maximumBytes)
    self.keep = max(0, keep)
  }

  deinit {
    if descriptor >= 0 { close(descriptor) }
  }

  /// Appends one line. Returns false when the log cannot be written.
  @discardableResult
  public func append(_ line: String) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    var data = Data(line.utf8)
    data.append(0x0A)
    guard ensureOpen() else { return false }
    if size > 0, size + data.count > maximumBytes {
      rotate()
      guard ensureOpen() else { return false }
    }
    guard writeAll(descriptor, data) else {
      closeDescriptor()
      return false
    }
    size += data.count
    return true
  }

  /// The most recent `count` lines across the current and rotated files, oldest
  /// first, reading at most `byteLimit` bytes in total.
  public func tail(lines count: Int, byteLimit: Int = 262_144) -> [String] {
    lock.lock()
    defer { lock.unlock() }
    var collected: [String] = []
    var remainingBytes = byteLimit
    let paths = [path] + (0..<keep).map { "\(path).\($0 + 1)" }
    for candidate in paths {
      guard collected.count < count, remainingBytes > 0,
        let (text, cut) = Self.readTail(candidate, limit: remainingBytes)
      else { continue }
      remainingBytes -= text.utf8.count
      var parts = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
      if cut, !parts.isEmpty { parts.removeFirst() }  // first line may be cut mid-line
      collected = parts + collected
    }
    return Array(collected.suffix(count))
  }

  // MARK: private

  private func ensureOpen() -> Bool {
    var onDisk = stat()
    let present = lstat(path, &onDisk) == 0
    if descriptor >= 0 {
      if present, onDisk.st_dev == device, onDisk.st_ino == inode,
        onDisk.st_mode & S_IFMT == S_IFREG
      {
        return true
      }
      closeDescriptor()
    }
    let opened = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard opened >= 0 else { return false }
    var info = stat()
    guard fstat(opened, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
      fchmod(opened, 0o600) == 0
    else {
      close(opened)
      return false
    }
    descriptor = opened
    device = info.st_dev
    inode = info.st_ino
    size = Int(info.st_size)
    return true
  }

  private func closeDescriptor() {
    if descriptor >= 0 { close(descriptor) }
    descriptor = -1
    size = 0
  }

  private func rotate() {
    closeDescriptor()
    guard keep > 0 else {
      unlink(path)
      return
    }
    unlink("\(path).\(keep)")
    for index in stride(from: keep - 1, through: 1, by: -1) {
      rename("\(path).\(index)", "\(path).\(index + 1)")
    }
    rename(path, "\(path).1")
  }

  private static func readTail(_ path: String, limit: Int) -> (String, Bool)? {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
    let length = min(Int(info.st_size), limit)
    guard length > 0, lseek(fd, off_t(Int(info.st_size) - length), SEEK_SET) >= 0 else {
      return nil
    }
    var buffer = [UInt8](repeating: 0, count: length)
    var offset = 0
    while offset < length {
      let count = buffer.withUnsafeMutableBytes {
        read(fd, $0.baseAddress!.advanced(by: offset), length - offset)
      }
      if count < 0, errno == EINTR { continue }
      if count <= 0 { break }
      offset += count
    }
    return (String(decoding: buffer[0..<offset], as: UTF8.self), Int(info.st_size) > length)
  }
}
