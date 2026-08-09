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

  @Test func signalCancelsActiveRuntimeThenEmitsOneClosedReport() async throws {
    let cancelledReport = makeReport(status: .cancelled, complete: false)
    let runtime = CancellationAwareRuntimeProbe(report: cancelledReport)
    let monitor = ManualPortalLoginSignalMonitor()
    let command = Task {
      try await runPortalLoginCommand(
        ["login"],
        runtime: { await runtime.run() },
        signalMonitorFactory: { monitor }
      )
    }

    #expect(runtime.waitUntilStarted())
    monitor.emit()
    let result = try await command.value

    #expect(result.exitCode == 2)
    #expect(runtime.invocationCount == 1)
    #expect(runtime.cancellationCount == 1)
    #expect(monitor.startCount == 1)
    #expect(monitor.stopCount == 1)
    let object = try #require(
      JSONSerialization.jsonObject(with: Data(result.standardOutput.utf8))
        as? [String: Any]
    )
    #expect(object["status"] as? String == "cancelled")
    #expect(object["transactionAccepted"] as? Bool == false)
    #expect(result.standardOutput.components(separatedBy: "\"schemaVersion\"").count == 2)
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

private final class ManualPortalLoginSignalMonitor: PortalLoginSignalMonitoring,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?
  private var starts = 0
  private var stops = 0

  func start(handler: @escaping @Sendable () -> Void) {
    lock.withLock {
      starts += 1
      self.handler = handler
    }
  }

  func stop() {
    lock.withLock {
      stops += 1
      handler = nil
    }
  }

  func emit() {
    let callback = lock.withLock { handler }
    callback?()
  }

  var startCount: Int { lock.withLock { starts } }
  var stopCount: Int { lock.withLock { stops } }
}

private final class CancellationAwareRuntimeProbe: @unchecked Sendable {
  private let lock = NSLock()
  private let started = DispatchSemaphore(value: 0)
  private let report: PortalLoginReport
  private var invocations = 0
  private var cancellations = 0

  init(report: PortalLoginReport) {
    self.report = report
  }

  func run() async -> PortalLoginReport {
    lock.withLock { invocations += 1 }
    started.signal()
    do {
      try await Task.sleep(for: .seconds(5))
    } catch {
      lock.withLock { cancellations += 1 }
    }
    return report
  }

  func waitUntilStarted() -> Bool {
    started.wait(timeout: .now() + 2) == .success
  }

  var invocationCount: Int { lock.withLock { invocations } }
  var cancellationCount: Int { lock.withLock { cancellations } }
}
