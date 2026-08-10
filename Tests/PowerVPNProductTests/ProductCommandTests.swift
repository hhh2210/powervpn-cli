import Foundation
import PowerVPNCore
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNProduct

@Suite struct ProductCommandTests {
  @Test(
    arguments: [
      ["doctor", "--json"],
      ["helper", "status", "--json"],
      ["resources", "--json"],
      ["snapshot", "--dry-run", "--json"],
    ]
  )
  func exactProductSurfacesEmitSortedJSON(_ arguments: [String]) throws {
    let result = try runProductCommand(arguments, runtime: blockedRuntime())
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )

    let expectedSchemaVersion =
      switch arguments.first {
      case "resources": 2
      case "snapshot": 3
      default: 1
      }
    #expect(object["schemaVersion"] as? Int == expectedSchemaVersion)
    #expect(object["productState"] as? String != nil)
    #expect(result.standardOutput.first == "{")
    #expect(result.standardOutput.contains("synthetic-secret") == false)
    #expect(
      result.exitCode == (arguments.first == "doctor" || arguments.first == "helper" ? 2 : 69))
  }

  @Test(
    arguments: [
      [] as [String],
      ["doctor"],
      ["doctor", "--json", "--json"],
      ["doctor", "--verbose", "--json"],
      ["helper", "--json", "status"],
      ["helper", "status"],
      ["helper", "status", "--probe", "--json"],
      ["resources", "--json", "extra"],
      ["snapshot", "--json", "--dry-run"],
      ["snapshot", "--dry-run"],
    ]
  )
  func malformedSurfacesFailClosed(_ arguments: [String]) {
    do {
      _ = try runProductCommand(arguments, runtime: blockedRuntime())
      Issue.record("expected usage rejection")
    } catch let error as ProductCommandError {
      #expect(error == .invalidArguments)
      #expect(error.description.hasPrefix("usage: powervpn"))
    } catch {
      Issue.record("unexpected error: \(error)")
    }
  }

  @Test func snapshotOutputNamesMissingFieldButContainsNoSnapshotValues() throws {
    let result = try runProductCommand(
      ["snapshot", "--dry-run", "--json"],
      runtime: blockedRuntime()
    )
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )

    #expect(object["firstMissingField"] as? String == "common.sessionid")
    #expect(object["snapshotComplete"] as? Bool == false)
    #expect(object["snapshotSerialized"] as? Bool == false)
    #expect(object["containsSecrets"] as? Bool == false)
    #expect(result.standardOutput.contains("gateway-value") == false)
    #expect(result.standardOutput.contains("psk-value") == false)
  }

  private func blockedRuntime() -> ProductReadinessRuntime {
    ProductReadinessRuntime(observer: ProductCommandFixedObservation())
  }
}

private struct ProductCommandFixedObservation: ProductReadinessObserving {
  func observe() -> ProductReadinessObservation {
    ProductReadinessObservation(
      installedVersion: "3.2.1",
      installedBuild: "24572",
      installedArchitectures: ["x86_64"],
      officialGUIRunning: false,
      helperAvailable: true,
      generation: VendorHelperGenerationSnapshot(
        launchdObserved: true,
        running: false,
        inactiveConfirmed: true,
        activeCount: 0,
        pid: nil,
        runs: 19
      ),
      directXPCStatus: .notProbed,
      directXPCPreflightSafe: true,
      profileSource: .sealedInstalledConfiguration,
      resourceSource: .unavailable,
      resourceCandidates: []
    )
  }
}
