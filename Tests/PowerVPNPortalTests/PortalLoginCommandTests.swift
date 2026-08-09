import Foundation
import Testing

@testable import PowerVPNCLI
@testable import PowerVPNPortal

@Suite struct PortalLoginCommandTests {
  @Test func acceptedTransactionEmitsOnlySortedClosedJSONAndReturnsZero() async throws {
    let report = makeReport(status: .accepted, complete: true)
    let result = try await runPortalLoginCommand(["login"]) { report }

    #expect(result.exitCode == 0)
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )
    #expect(
      Set(object.keys) == [
        "mode", "operations", "ownedMaterial", "safety", "schemaVersion", "status",
        "transactionAccepted",
      ]
    )
    #expect(object["transactionAccepted"] as? Bool == true)
    assertTopLevelKeysAreSorted(result.standardOutput)
  }

  @Test func nonacceptedTransactionStillEmitsClosedJSONAndReturnsTwo() async throws {
    let report = makeReport(status: .configurationRejected, complete: false)
    let result = try await runPortalLoginCommand(["login"]) { report }

    #expect(result.exitCode == 2)
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )
    #expect(object["status"] as? String == "configuration_rejected")
    #expect(object["transactionAccepted"] as? Bool == false)
  }

  @Test func incompleteAcceptedStatusReturnsTwo() async throws {
    let report = makeReport(status: .accepted, complete: false)
    let result = try await runPortalLoginCommand(["login"]) { report }

    #expect(!report.transactionAccepted)
    #expect(result.exitCode == 2)
  }

  @Test(
    arguments: [
      [] as [String],
      ["login", "--json"],
      ["login", "--gateway", "portal.example.invalid"],
      ["login", "--config", "/synthetic/config"],
      ["login", "--file", "/synthetic/input"],
      ["login", "--env", "SYNTHETIC"],
      ["login", "--stdin"],
      ["login", "--password", "synthetic"],
      ["login", "synthetic-user"],
    ]
  )
  func invalidSurfaceFailsBeforeRuntime(_ arguments: [String]) async {
    let invocation = RuntimeInvocationProbe()

    do {
      _ = try await runPortalLoginCommand(arguments) {
        invocation.mark()
        return makeReport(status: .accepted, complete: true)
      }
      Issue.record("expected usage rejection")
    } catch let error as PortalLoginCommandError {
      #expect(error == .invalidArguments)
      #expect(error.description == "usage: powervpn login")
    } catch {
      Issue.record("unexpected error: \(error)")
    }

    #expect(invocation.count == 0)
  }

  private func assertTopLevelKeysAreSorted(_ json: String) {
    let keys = [
      "mode", "operations", "ownedMaterial", "safety", "schemaVersion", "status",
      "transactionAccepted",
    ]
    let offsets = keys.compactMap { json.range(of: "\"\($0)\"")?.lowerBound }
    #expect(offsets.count == keys.count)
    #expect(zip(offsets, offsets.dropFirst()).allSatisfy(<))
  }

  private func makeReport(
    status: PortalLoginStatus,
    complete: Bool
  ) -> PortalLoginReport {
    PortalLoginReport(
      status: status,
      operations: PortalOperationEvidence(
        loginRequested: complete,
        loginAccepted: complete,
        sessionCheckRequested: complete,
        sessionCheckAccepted: complete,
        resourceListRequested: complete,
        resourceListAccepted: complete,
        logoutRequested: complete,
        logoutAccepted: complete
      ),
      ownedMaterial: PortalOwnedMaterialEvidence(
        credentialsErased: true,
        requestBodiesErased: true,
        responseBodiesErased: true,
        sessionMaterialErased: true
      )
    )
  }
}

private final class RuntimeInvocationProbe: @unchecked Sendable {
  private let lock = NSLock()
  private var invocationCount = 0

  func mark() {
    lock.withLock { invocationCount += 1 }
  }

  var count: Int { lock.withLock { invocationCount } }
}
