import Foundation
import Testing

@testable import PowerVPNCLI

@Suite struct LegacyNetworkCommandTests {
  @Test(arguments: ["probe", "diagnose"])
  func legacyNetworkCommandsAreBlockedWithoutSideEffects(_ command: String) throws {
    let result = try runLegacyNetworkCommand([command, "--json"])
    #expect(result.exitCode == 69)
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )
    #expect(object["outcome"] as? String == "explicit_m2_approval_required")
    #expect(object["networkRequested"] as? Bool == false)
    #expect(object["helperMutationRequested"] as? Bool == false)
    #expect(object["containsSecrets"] as? Bool == false)
  }

  @Test func legacyArgumentsCannotReenableTheOldNetworkPath() {
    let rejected = [
      ["probe", "--timeout", "5"],
      ["diagnose", "--timeout", "5", "--json"],
      ["probe", "--yes"],
      ["diagnose", "--target", "thu21"],
    ]
    for arguments in rejected {
      #expect(throws: LegacyNetworkCommandError.invalidArguments) {
        try runLegacyNetworkCommand(arguments)
      }
    }
  }
}
