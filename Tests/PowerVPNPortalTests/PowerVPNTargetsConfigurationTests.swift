import Darwin
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PowerVPNTargetsConfigurationTests {
  @Test func decodesClosedSyntheticSchemaAndArbitraryThirdTarget() throws {
    let configuration = try PowerVPNTargetsConfiguration.decode(
      syntheticTargetsJSON(
        targets: """
          "lab-a": {"host":"192.0.2.21","user":"synthetic-user"},
          "lab-b": {"host":"192.0.2.52","user":"synthetic-user"},
          "lab-third": {"host":"198.51.100.7","user":"third_user"}
          """))

    #expect(configuration.portalOrigin.absoluteString == "https://192.0.2.1:4443")
    let third = try configuration.target(named: "lab-third")
    #expect(third.host == "198.51.100.7")
    #expect(third.ipv4 == 0xC633_6407)
    #expect(third.user == "third_user")
    #expect(throws: PowerVPNTargetsConfigurationError.targetUnknown) {
      _ = try configuration.target(named: "absent")
    }
  }

  @Test func malformedExtraAndCredentialShapedFieldsFailClosed() {
    for data in [
      syntheticTargetsJSON(
        topLevelSuffix: ",\"PORTAL_PASSWORD\":\"must-not-be-accepted\""),
      syntheticTargetsJSON(targetSuffix: ",\"session\":\"must-not-be-accepted\""),
      Data("{\"portalOrigin\":\"http://192.0.2.1:4443\",\"targets\":{}}".utf8),
      Data("{\"portalOrigin\":\"https://192.0.2.1:4443/path\",\"targets\":{}}".utf8),
      syntheticTargetsJSON(host: "lab.example"),
      syntheticTargetsJSON(host: "192.0.2.01"),
      syntheticTargetsJSON(user: "unsafe user"),
    ] {
      #expect(throws: PowerVPNTargetsConfigurationError.invalid) {
        _ = try PowerVPNTargetsConfiguration.decode(data)
      }
    }
  }

  @Test func protectedFileRequiresOwnedRegular0600AndClassifiesMissing() throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("powervpn-targets-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("targets.json").path
    #expect(throws: PowerVPNTargetsConfigurationError.missing) {
      _ = try PowerVPNTargetsConfiguration.read(path: path)
    }

    try syntheticTargetsJSON().write(to: URL(fileURLWithPath: path))
    #expect(chmod(path, 0o600) == 0)
    #expect(
      try PowerVPNTargetsConfiguration.read(path: path).target(named: "lab-a").user
        == "synthetic-user")

    #expect(chmod(path, 0o644) == 0)
    #expect(throws: PowerVPNTargetsConfigurationError.invalid) {
      _ = try PowerVPNTargetsConfiguration.read(path: path)
    }

    let symlinkPath = directory.appendingPathComponent("targets-link.json").path
    #expect(symlink(path, symlinkPath) == 0)
    #expect(throws: PowerVPNTargetsConfigurationError.invalid) {
      _ = try PowerVPNTargetsConfiguration.read(path: symlinkPath)
    }
  }
}

private func syntheticTargetsJSON(
  host: String = "192.0.2.21",
  user: String = "synthetic-user",
  targets: String? = nil,
  targetSuffix: String = "",
  topLevelSuffix: String = ""
) -> Data {
  let targetObject =
    targets ?? "\"lab-a\":{\"host\":\"\(host)\",\"user\":\"\(user)\"\(targetSuffix)}"
  return Data(
    "{\"portalOrigin\":\"https://192.0.2.1:4443\",\"targets\":{\(targetObject)}\(topLevelSuffix)}"
      .utf8
  )
}
