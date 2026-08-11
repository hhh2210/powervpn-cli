import Foundation
import Testing

@testable import PowerVPNCLI

@Suite struct VendorOnceCommandTests {
  @Test func exactBeginPersistsOneValueFreeBoundary() throws {
    let trace = VendorOnceCommandTrace()
    let result = try runVendorOnceCommand(
      ["vendor-once", "begin", "--json"],
      begin: { trace.record() }
    )

    #expect(result.exitCode == 0)
    #expect(trace.count == 1)
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )
    #expect(object["schemaVersion"] as? Int == 1)
    #expect(object["outcome"] as? String == "armed")
    #expect(object["onboardingMode"] as? String == "vendor_once")
    #expect(object["cursorPersisted"] as? Bool == true)
    #expect(object["containsSecrets"] as? Bool == false)
    #expect(object["serverContactRequested"] as? Bool == false)
    #expect(object["helperMutationRequested"] as? Bool == false)
    #expect(!result.standardOutput.contains("device"))
    #expect(!result.standardOutput.contains("inode"))
    #expect(!result.standardOutput.contains("size"))
  }

  @Test func rejectedBoundaryIsValueFreeAndNeverClaimsPersistence() throws {
    let result = try runVendorOnceCommand(
      ["vendor-once", "begin", "--json"],
      begin: { throw VendorOnceTestError.rejected }
    )

    #expect(result.exitCode == 69)
    #expect(result.standardOutput.contains("\"outcome\" : \"cursor_rejected\""))
    #expect(result.standardOutput.contains("\"cursorPersisted\" : false"))
    #expect(result.standardOutput.contains("\"containsSecrets\" : false"))
  }

  @Test func malformedGrammarNeverCapturesBoundary() {
    for arguments in [
      ["vendor-once", "begin"],
      ["vendor-once", "begin", "--json", "--yes"],
      ["vendor-once", "status", "--json"],
    ] {
      let trace = VendorOnceCommandTrace()
      #expect(throws: VendorOnceCommandError.invalidArguments) {
        _ = try runVendorOnceCommand(arguments, begin: { trace.record() })
      }
      #expect(trace.count == 0)
    }
  }
}

private enum VendorOnceTestError: Error { case rejected }

private final class VendorOnceCommandTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var storedCount = 0

  func record() { lock.withLock { storedCount += 1 } }
  var count: Int { lock.withLock { storedCount } }
}
