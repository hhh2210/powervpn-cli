import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNCore

@Suite struct NativeHomebrewTests {
  private static let payloadFiles = [
    "install.sh", "uninstall.sh", "powervpn-native-helper", "runtime.tar", "runtime.sha256",
  ]

  private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("native-homebrew-\(UUID().uuidString)").resolvingSymlinksInPath()
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
  }

  /// A keg laid out like Homebrew's: <keg>/bin/powervpn, <keg>/libexec/powervpn-native/*,
  /// reached through a <brew>/bin/powervpn symlink.
  private func makeKeg(in root: URL, files: [String] = payloadFiles) throws -> (
    link: String, payload: String
  ) {
    let keg = root.appendingPathComponent("Cellar/powervpn/0.2.0")
    let payload = keg.appendingPathComponent("libexec/powervpn-native")
    try FileManager.default.createDirectory(
      at: keg.appendingPathComponent("bin"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: payload, withIntermediateDirectories: true)
    try Data("cli".utf8).write(to: keg.appendingPathComponent("bin/powervpn"))
    for file in files {
      try Data("bundled \(file)".utf8).write(to: payload.appendingPathComponent(file))
    }
    let bin = root.appendingPathComponent("bin")
    try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
    let link = bin.appendingPathComponent("powervpn").path
    try FileManager.default.createSymbolicLink(
      atPath: link, withDestinationPath: "../Cellar/powervpn/0.2.0/bin/powervpn")
    return (link, payload.path)
  }

  @Test func locatesTheKegPayloadThroughTheBrewSymlinkOnlyWhenComplete() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let keg = try makeKeg(in: root)
    #expect(NativeBundledPayload.locate(executablePath: keg.link)?.directory == keg.payload)

    try FileManager.default.removeItem(atPath: keg.payload + "/runtime.sha256")
    #expect(NativeBundledPayload.locate(executablePath: keg.link) == nil)
    #expect(NativeBundledPayload.locate(executablePath: nil) == nil)
  }

  @Test func comparesTheInstalledHelperAndRuntimeManifestWithTheKeg() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = NativeBundledPayload(directory: try makeKeg(in: root).payload)
    let home = root.appendingPathComponent("home").path
    try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
    #expect(payload.matchesInstalled(home: home) == nil)

    try FileManager.default.copyItem(
      atPath: payload.helper, toPath: home + "/powervpn-native-helper")
    // An install from before the manifest existed must count as outdated.
    #expect(payload.matchesInstalled(home: home) == false)
    try FileManager.default.copyItem(
      atPath: payload.runtimeManifest, toPath: home + "/runtime.sha256")
    #expect(payload.matchesInstalled(home: home) == true)

    try Data("other runtime".utf8).write(to: URL(fileURLWithPath: home + "/runtime.sha256"))
    #expect(payload.matchesInstalled(home: home) == false)
  }

  @Test func installRequiresSudoAndPassesOnlyThePayloadAndOwner() throws {
    let payload = NativeBundledPayload(directory: "/keg/libexec/powervpn-native")
    var calls: [(String, [String: String])] = []
    let record: (String, [String: String]) -> Int32 = { script, environment in
      calls.append((script, environment))
      return 0
    }
    let notRoot = runNativeCommand(
      ["native", "install"], payload: payload, invokedPath: "/opt/homebrew/bin/powervpn",
      effectiveUserID: 501, environment: ["SUDO_UID": "501"], runScript: record)
    #expect(notRoot.exitCode == 77)
    #expect(notRoot.standardError.contains("next: sudo /opt/homebrew/bin/powervpn native install"))
    #expect(
      NativeBundledPayload.sudoCommand("install", invokedAs: "powervpn")
        == "sudo powervpn native install")
    let rootWithoutOwner = runNativeCommand(
      ["native", "install"], payload: payload, effectiveUserID: 0, environment: [:],
      runScript: record)
    #expect(rootWithoutOwner.exitCode == 77)
    #expect(calls.isEmpty)

    let installed = runNativeCommand(
      ["native", "install"], payload: payload, effectiveUserID: 0,
      environment: [
        "SUDO_UID": "501", "POWERVPN_NATIVE_RUNTIME": "/tmp/elsewhere",
        "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib",
      ],
      runScript: record)
    #expect(installed.exitCode == 0)
    #expect(calls.count == 1)
    #expect(calls.first?.0 == payload.installScript)
    #expect(
      calls.first?.1 == [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_UID": "501",
        "POWERVPN_NATIVE_RUNTIME_ARCHIVE": payload.runtimeArchive,
        "POWERVPN_NATIVE_HELPER": payload.helper,
      ])

    _ = runNativeCommand(
      ["native", "uninstall"], payload: payload, effectiveUserID: 0,
      environment: ["SUDO_UID": "501"], runScript: record)
    #expect(calls.last?.0 == payload.uninstallScript)
    #expect(calls.last?.1 == ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_UID": "501"])
  }

  @Test func statusAndSourceCheckoutsNameTheRightNextStep() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let payload = NativeBundledPayload(directory: try makeKeg(in: root).payload)
    let home = root.appendingPathComponent("home").path
    try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)

    let missing = runNativeCommand(
      ["native", "status"], payload: payload, installedHome: home)
    #expect(missing.exitCode == 1)
    #expect(missing.standardError.contains("not installed"))
    for file in ["powervpn-native-helper", "runtime.sha256"] {
      try FileManager.default.copyItem(
        atPath: payload.directory + "/" + file, toPath: home + "/" + file)
    }
    let current = runNativeCommand(
      ["native", "status"], payload: payload, installedHome: home)
    #expect(current.exitCode == 0)
    #expect(current.standardOutput.contains("up to date"))

    let source = runNativeCommand(["native", "install"], payload: nil)
    #expect(source.exitCode == 77)
    #expect(source.standardError.contains("scripts/native/install.sh"))
    #expect(runNativeCommand(["native", "frobnicate"], payload: payload).exitCode == 64)
  }
}
