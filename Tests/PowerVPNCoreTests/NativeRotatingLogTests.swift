import Darwin
import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeRotatingLogTests {
  private func directory() throws -> String {
    let path = NSTemporaryDirectory() + "powervpn-log-" + UUID().uuidString
    try FileManager.default.createDirectory(
      atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return path
  }

  @Test func appendsPrivatelyAndTailsInOrder() throws {
    let dir = try directory()
    defer { try? FileManager.default.removeItem(atPath: dir) }
    let log = NativeRotatingLog(path: dir + "/a.log")
    for index in 1...5 { log.append("line \(index)") }
    #expect(log.tail(lines: 3) == ["line 3", "line 4", "line 5"])
    var info = stat()
    #expect(stat(dir + "/a.log", &info) == 0 && info.st_mode & 0o777 == 0o600)
  }

  @Test func rotationBoundsTheDiskAndKeepsNewestLines() throws {
    let dir = try directory()
    defer { try? FileManager.default.removeItem(atPath: dir) }
    let log = NativeRotatingLog(path: dir + "/a.log", maximumBytes: 1_024, keep: 2)
    for index in 1...200 {
      log.append(String(format: "entry %04d ", index) + String(repeating: "x", count: 40))
    }
    let files = try FileManager.default.contentsOfDirectory(atPath: dir).sorted()
    #expect(files == ["a.log", "a.log.1", "a.log.2"])
    for name in files {
      let size = try FileManager.default.attributesOfItem(atPath: dir + "/" + name)[.size] as? Int
      #expect((size ?? 0) <= 1_024)
    }
    #expect(log.tail(lines: 1).first?.hasPrefix("entry 0200") == true)
    // The tail spans the rotation boundary.
    #expect(log.tail(lines: 40).count == 40)
  }

  @Test func reopensAfterTheFileIsUnlinkedWhileRunning() throws {
    let dir = try directory()
    defer { try? FileManager.default.removeItem(atPath: dir) }
    let log = NativeRotatingLog(path: dir + "/a.log")
    log.append("before")
    unlink(dir + "/a.log")
    log.append("after")
    #expect(log.tail(lines: 5) == ["after"])
  }

  @Test func refusesToFollowASymlink() throws {
    let dir = try directory()
    defer { try? FileManager.default.removeItem(atPath: dir) }
    try "target".write(toFile: dir + "/target", atomically: true, encoding: .utf8)
    symlink(dir + "/target", dir + "/a.log")
    let log = NativeRotatingLog(path: dir + "/a.log")
    #expect(!log.append("nope"))
    #expect(try String(contentsOfFile: dir + "/target", encoding: .utf8) == "target")
  }
}
