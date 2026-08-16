import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VendorCharonControlCommitTests {
  @Test func cancellationRaisedByCommitStillSubmitsAndRetainsCleanupCapability() async throws {
    let factory = CharonControlDriverFactory()
    let trace = ControlCommitTrace()
    let snapshot = try ControlSnapshotFixture().snapshot()

    let result = try await Task { () throws -> VendorCharonStartControlResult in
      let pending = try controlTransport(factory).beginStart(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true },
        commitStartAuthorization: { trace.recordAndCancelCurrentTask() }
      )
      return await pending.result()
    }.value

    #expect(trace.count == 1)
    #expect(factory.callCount == 1)
    #expect(factory.driver.submitCount == 1)
    #expect(result.receipt.outcome == .cancelled)
    #expect(result.receipt.requestSent)
    #expect(result.lease == nil)
    let cleanup = try #require(result.provisionalStopCapability)

    let stop = Task { await cleanup.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 1)
    let receipt = await stop.value
    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.requestSent)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 0)
    withExtendedLifetime(cleanup) {}
  }

  @Test func cancellationBeforeCoreGateConsumesAndSubmitsNothing() async throws {
    let factory = CharonControlDriverFactory()
    let trace = ControlCommitTrace()
    let snapshot = try ControlSnapshotFixture().snapshot()

    let result = try await Task { () throws -> VendorCharonStartControlResult in
      withUnsafeCurrentTask { $0?.cancel() }
      let pending = try controlTransport(factory).beginStart(
        snapshot: snapshot,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true },
        commitStartAuthorization: { trace.record() }
      )
      return await pending.result()
    }.value

    #expect(result.receipt.outcome == .cancelled)
    #expect(!result.receipt.requestSent)
    #expect(result.provisionalStopCapability == nil)
    #expect(trace.count == 0)
    #expect(factory.callCount == 0)
    #expect(factory.driver.submitCount == 0)
  }

  @Test func throwingCommitDoesNotCreateDriverOrSubmit() throws {
    enum Injected: Error { case rejected }
    let factory = CharonControlDriverFactory()
    let trace = ControlCommitTrace()

    #expect(throws: Injected.self) {
      _ = try controlTransport(factory).beginStart(
        snapshot: ControlSnapshotFixture().snapshot(),
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true },
        commitStartAuthorization: {
          trace.record()
          throw Injected.rejected
        }
      )
    }
    #expect(trace.count == 1)
    #expect(factory.callCount == 0)
    #expect(factory.driver.submitCount == 0)
  }

  @Test func encodingFailurePrecedesAuthorizationCommitAndSubmission() async throws {
    let factory = CharonControlDriverFactory()
    let trace = ControlCommitTrace()
    let fixture = ControlSnapshotFixture()
    let snapshot = try fixture.snapshot()
    fixture.session.failBorrows()

    let pending = try controlTransport(factory).beginStart(
      snapshot: snapshot,
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: { trace.record() }
    )
    let result = await pending.result()

    #expect(result.receipt.outcome == .snapshotEncodingFailed)
    #expect(result.receipt.encodingError == .textMaterialUnavailable(.sessionID))
    #expect(!result.receipt.requestSent)
    #expect(trace.count == 0)
    #expect(factory.callCount == 0)
    #expect(factory.driver.submitCount == 0)
  }

  @Test func unboundMultiTunnelFailsBeforeAuthorizationCommitAndSubmission() async throws {
    let factory = CharonControlDriverFactory()
    let trace = ControlCommitTrace()
    let snapshot = try ControlSnapshotFixture().snapshot(
      tunnelNames: ["synthetic-tunnel-first", "synthetic-tunnel-second"]
    )

    let pending = try controlTransport(factory).beginStart(
      snapshot: snapshot,
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true },
      commitStartAuthorization: { trace.record() }
    )
    let result = await pending.result()

    #expect(result.receipt.outcome == .snapshotEncodingFailed)
    #expect(result.receipt.encodingError == .incompleteSnapshot(.tunnelName))
    #expect(!result.receipt.requestSent)
    #expect(trace.count == 0)
    #expect(factory.callCount == 0)
    #expect(factory.driver.submitCount == 0)
  }
}

private final class ControlCommitTrace: @unchecked Sendable {
  private let lock = NSLock()
  private var commits = 0

  var count: Int { lock.withLock { commits } }

  func record() {
    lock.withLock { commits += 1 }
  }

  func recordAndCancelCurrentTask() {
    record()
    withUnsafeCurrentTask { $0?.cancel() }
  }
}
