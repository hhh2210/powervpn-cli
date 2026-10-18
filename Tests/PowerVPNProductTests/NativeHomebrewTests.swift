import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore

@Suite struct NativeHomebrewTests {
  private static let payloadFiles = [
    "install.sh", "uninstall.sh", "powervpn-native-helper", "runtime.tar",
  ]

  private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("native-homebrew-\(UUID().uuidString)").resolvingSymlinksInPath()
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  private func tar(_ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
    process.arguments = arguments
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 0)
  }

  /// A keg laid out like Homebrew's: <keg>/bin/powervpn, <keg>/libexec/powervpn-native/*,
  /// reached through a <brew>/bin/powervpn symlink. runtime.tar is a real tar
  /// holding a charon, a library and a symlink to it.
  private func makeKeg(in root: URL, files: [String] = payloadFiles) throws -> (
    link: String, payload: String
  ) {
    let keg = root.appendingPathComponent("Cellar/powervpn/0.2.0")
    let payload = keg.appendingPathComponent("libexec/powervpn-native")
    try FileManager.default.createDirectory(
      at: keg.appendingPathComponent("bin"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: payload, withIntermediateDirectories: true)
    try Data("cli".utf8).write(to: keg.appendingPathComponent("bin/powervpn"))
    for file in files where file != "runtime.tar" {
      try Data("bundled \(file)".utf8).write(to: payload.appendingPathComponent(file))
    }
    if files.contains("runtime.tar") {
      let tree = root.appendingPathComponent("runtime-tree")
      for directory in ["libexec/ipsec", "lib/ipsec"] {
        try FileManager.default.createDirectory(
          at: tree.appendingPathComponent(directory), withIntermediateDirectories: true)
      }
      try Data("charon".utf8).write(to: tree.appendingPathComponent("libexec/ipsec/charon"))
      try Data("lib".utf8).write(to: tree.appendingPathComponent("lib/ipsec/libcharon.0.dylib"))
      try FileManager.default.createSymbolicLink(
        atPath: tree.appendingPathComponent("lib/ipsec/libcharon.dylib").path,
        withDestinationPath: "libcharon.0.dylib")
      try tar(["-cf", payload.appendingPathComponent("runtime.tar").path, "-C", tree.path, "."])
    }
    let bin = root.appendingPathComponent("bin")
    try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
    let link = bin.appendingPathComponent("powervpn").path
    try FileManager.default.createSymbolicLink(
      atPath: link, withDestinationPath: "../Cellar/powervpn/0.2.0/bin/powervpn")
    return (link, payload.path)
  }

  /// A root install made from `payload`, as install.sh lays it out.
  private func install(_ payload: NativeBundledPayload, into home: String) throws {
    try FileManager.default.createDirectory(
      atPath: home + "/runtime", withIntermediateDirectories: true)
    try tar(["-xf", payload.runtimeArchive, "-C", home + "/runtime"])
    for file in ["strongswan.conf", "allowed-hosts", "owner-uid"] {
      try Data("installed".utf8).write(to: URL(fileURLWithPath: home + "/" + file))
    }
    try FileManager.default.copyItem(
      atPath: payload.helper, toPath: home + "/powervpn-native-helper")
    try #require(payload.expectedInstalledFrom())
      .write(toFile: home + "/installed-from", atomically: true, encoding: .utf8)
  }

  @Test func locatesTheKegThroughTheBrewSymlinkEvenWhenInstallFilesAreMissing() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let keg = try makeKeg(in: root)
    let found = try #require(NativeBundledPayload.locate(executablePath: keg.link))
    #expect(found.directory == keg.payload)
    #expect(found.installFilesPresent)

    try FileManager.default.removeItem(atPath: keg.payload + "/runtime.tar")
    let partial = try #require(NativeBundledPayload.locate(executablePath: keg.link))
    #expect(!partial.installFilesPresent)
    try FileManager.default.removeItem(atPath: keg.payload + "/uninstall.sh")
    #expect(NativeBundledPayload.locate(executablePath: keg.link) == nil)
    #expect(NativeBundledPayload.locate(executablePath: nil) == nil)
  }

  @Test func detectsAnyKegChangeAndAnIncompleteRootInstall() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = NativeBundledPayload(directory: try makeKeg(in: root).payload)
    let home = root.appendingPathComponent("home").path
    try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
    #expect(payload.matchesInstalled(home: home) == nil)

    try install(payload, into: home)
    #expect(payload.matchesInstalled(home: home) == true)

    // An installer-only change (e.g. a new strongswan.conf) must count too.
    for file in ["install.sh", "powervpn-native-helper", "runtime.tar"] {
      let path = payload.directory + "/" + file
      let original = try Data(contentsOf: URL(fileURLWithPath: path))
      try Data("changed".utf8).write(to: URL(fileURLWithPath: path))
      #expect(payload.matchesInstalled(home: home) == false)
      try original.write(to: URL(fileURLWithPath: path))
    }
    #expect(payload.matchesInstalled(home: home) == true)

    // A missing library, or a missing symlink to it, is not up to date.
    for member in ["lib/ipsec/libcharon.0.dylib", "lib/ipsec/libcharon.dylib"] {
      let path = home + "/runtime/" + member
      let backup = home + "/backup"
      try FileManager.default.moveItem(atPath: path, toPath: backup)
      #expect(payload.matchesInstalled(home: home) == false)
      try FileManager.default.moveItem(atPath: backup, toPath: path)
    }
    #expect(payload.matchesInstalled(home: home) == true)
    try FileManager.default.removeItem(atPath: home + "/runtime/libexec/ipsec/charon")
    #expect(payload.matchesInstalled(home: home) == false)
  }

  @Test func installRequiresSudoAndPassesOnlyThePayloadAndOwner() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = NativeBundledPayload(directory: try makeKeg(in: root).payload)
    let home = root.appendingPathComponent("home").path
    var calls: [(String, [String: String])] = []
    var notices: [String] = []
    let record: (String, [String: String]) -> Int32 = { script, environment in
      calls.append((script, environment))
      return 0
    }
    let notRoot = runNativeCommand(
      ["native", "install"], payload: payload, installedHome: home,
      invokedPath: "/opt/homebrew/bin/powervpn", effectiveUserID: 501,
      environment: ["SUDO_UID": "501"], runScript: record)
    #expect(notRoot.exitCode == 77)
    #expect(notRoot.standardError.contains("next: sudo /opt/homebrew/bin/powervpn native install"))
    let rootWithoutOwner = runNativeCommand(
      ["native", "install"], payload: payload, installedHome: home, effectiveUserID: 0,
      environment: [:], runScript: record)
    #expect(rootWithoutOwner.exitCode == 77)
    #expect(calls.isEmpty)

    let installed = runNativeCommand(
      ["native", "install"], payload: payload, installedHome: home, effectiveUserID: 0,
      environment: [
        "SUDO_UID": "501", "POWERVPN_NATIVE_RUNTIME": "/tmp/elsewhere",
        "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib",
      ],
      notice: { notices.append($0) }, runScript: record)
    #expect(installed.exitCode == 0)
    #expect(notices.isEmpty)
    #expect(calls.count == 1)
    #expect(calls.first?.0 == payload.installScript)
    #expect(
      calls.first?.1 == [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_UID": "501",
        "POWERVPN_NATIVE_RUNTIME_ARCHIVE": payload.runtimeArchive,
        "POWERVPN_NATIVE_HELPER": payload.helper,
      ])

    // Reinstalling over a running backend warns that the session drops.
    try install(payload, into: home)
    _ = runNativeCommand(
      ["native", "install"], payload: payload, installedHome: home, effectiveUserID: 0,
      environment: ["SUDO_UID": "501"], notice: { notices.append($0) }, runScript: record)
    #expect(notices.count == 1)
    #expect(notices.first?.contains("session drops") == true)
  }

  @Test func uninstallWorksFromAnIncompleteKegButInstallDoesNot() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = NativeBundledPayload(
      directory: try makeKeg(in: root, files: ["uninstall.sh"]).payload)
    var scripts: [String] = []
    let record: (String, [String: String]) -> Int32 = { script, _ in
      scripts.append(script)
      return 0
    }
    let install = runNativeCommand(
      ["native", "install"], payload: payload, effectiveUserID: 0,
      environment: ["SUDO_UID": "501"], runScript: record)
    #expect(install.exitCode == 77)
    #expect(install.standardError.contains("brew reinstall"))
    let uninstall = runNativeCommand(
      ["native", "uninstall"], payload: payload, effectiveUserID: 0,
      environment: ["SUDO_UID": "501"], notice: { _ in }, runScript: record)
    #expect(uninstall.exitCode == 0)
    #expect(scripts == [payload.uninstallScript])
  }

  @Test func statusAndSourceCheckoutsNameTheRightNextStep() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = NativeBundledPayload(directory: try makeKeg(in: root).payload)
    let home = root.appendingPathComponent("home").path
    try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)

    let missing = runNativeCommand(["native", "status"], payload: payload, installedHome: home)
    #expect(missing.exitCode == 1)
    #expect(missing.standardError.contains("not installed"))
    try install(payload, into: home)
    let current = runNativeCommand(["native", "status"], payload: payload, installedHome: home)
    #expect(current.exitCode == 0)
    #expect(current.standardOutput.contains("up to date"))

    let source = runNativeCommand(["native", "install"], payload: nil)
    #expect(source.exitCode == 77)
    #expect(source.standardError.contains("scripts/native/install.sh"))
    #expect(runNativeCommand(["native", "frobnicate"], payload: payload).exitCode == 64)
  }

  @Test func nextLinesQuoteTheCLIPathForTheShell() {
    let command = NativeBundledPayload.sudoCommand
    #expect(
      command("install", "/opt/homebrew/bin/powervpn")
        == "sudo /opt/homebrew/bin/powervpn native install")
    #expect(
      command("install", "/Users/a b/bin/powervpn")
        == "sudo '/Users/a b/bin/powervpn' native install")
    #expect(command("install", "/tmp/x;id/powervpn") == "sudo '/tmp/x;id/powervpn' native install")
    #expect(
      command("install", "/tmp/it's/powervpn")
        == "sudo '/tmp/it'\\''s/powervpn' native install")
    #expect(command("uninstall", nil) == "sudo powervpn native uninstall")
    // A relative invocation is resolved to an absolute path, never left relative.
    #expect(command("install", "bin/powervpn").hasPrefix("sudo /"))
  }
}
