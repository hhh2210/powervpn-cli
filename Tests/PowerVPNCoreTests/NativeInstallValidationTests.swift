import Darwin
import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct NativeInstallValidationTests {
  @Test func validatesHostsWithoutTrustingArbitraryIPv4Input() {
    #expect(NativeHostPolicy.parse("192.0.2.21\n192.0.2.52\n") == ["192.0.2.21", "192.0.2.52"])
    for input in ["", "0.0.0.0", "127.0.0.1", "192.0.2.052", "192.0.2.1/24", "192.0.2.1\ninvalid"] {
      #expect(NativeHostPolicy.parse(input) == nil)
    }
  }

  @Test func rejectsACLsWritableFilesExternalSymlinksAndHardlinks() throws {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("native-install-\(UUID().uuidString)").resolvingSymlinksInPath()
    try FileManager.default.createDirectory(
      at: root, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("runtime")
    try Data("synthetic".utf8).write(to: file)
    #expect(chmod(file.path, 0o600) == 0)
    #expect(NativeInstallValidation.hasNoACL(file.path))
    #expect(NativeInstallValidation.validateTree(root.path, owner: getuid()))

    #expect(chmod(file.path, 0o620) == 0)
    #expect(!NativeInstallValidation.validateTree(root.path, owner: getuid()))
    #expect(chmod(file.path, 0o600) == 0)

    let link = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(
      atPath: link.path, withDestinationPath: "/usr/bin/true")
    #expect(!NativeInstallValidation.validateTree(root.path, owner: getuid()))
    try FileManager.default.removeItem(at: link)
    try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "runtime")
    #expect(NativeInstallValidation.validateTree(root.path, owner: getuid()))
    try FileManager.default.removeItem(at: link)
    #expect(Darwin.link(file.path, link.path) == 0)
    #expect(!NativeInstallValidation.validateTree(root.path, owner: getuid()))
    try FileManager.default.removeItem(at: link)

    let chmodProcess = Process()
    chmodProcess.executableURL = URL(fileURLWithPath: "/bin/chmod")
    chmodProcess.arguments = ["+a", "\(NSUserName()) allow write", file.path]
    try chmodProcess.run()
    chmodProcess.waitUntilExit()
    #expect(chmodProcess.terminationStatus == 0)
    #expect(!NativeInstallValidation.hasNoACL(file.path))
    #expect(!NativeInstallValidation.validateTree(root.path, owner: getuid()))
  }

  @Test func unknownSAQueryNeverConfirmsAbsence() {
    #expect(!NativeIKELookup.unknown.confirmsAbsence)
    #expect(NativeIKELookup.absent.confirmsAbsence)
  }
}
