import Foundation
import Testing
@preconcurrency import XPC

@testable import PowerVPNCore

@Suite struct VendorCharonNCRouteToggleTests {
  @Test func enableDisableAndStopReuseOneRetainedDriver() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)

    let enableTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    #expect(factory.driver.observations[1].exactNCRouteToggleShape)
    #expect(factory.driver.observations[1].ncRouteEnabled == true)
    #expect(factory.driver.observations[1].tunnelName == "synthetic-tunnel")
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 1)
    let enable = await enableTask.value

    #expect(enable.operation == .resourceToggleNC)
    #expect(enable.outcome == .transportAcknowledged)
    #expect(enable.requestSent)
    #expect(enable.helperSuccessEstablished)
    #expect(enable.connectionRetained)
    #expect(enable.replySignatures == ["1:reply:updown_nc_success:bool"])
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 1)
    #expect(factory.driver.submitCount == 2)
    let disableTask = Task {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    #expect(factory.driver.observations[2].exactNCRouteToggleShape)
    #expect(factory.driver.observations[2].ncRouteEnabled == false)
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 2)
    let disable = await disableTask.value

    #expect(disable.outcome == .transportAcknowledged)
    #expect(disable.helperSuccessEstablished)
    #expect(disable.connectionRetained)

    let stopTask = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 4 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 3)
    let stop = await stopTask.value

    #expect(stop.outcome == .transportAcknowledged)
    #expect(factory.driver.observations[3].exactStopShape)
    #expect(factory.callCount == 1)
    #expect(factory.driver.cancelCount == 0)
  }

  @Test func twoTunnelSelectedSecondTargetsOnlySecondForEnableAndDisable() async throws {
    let factory = CharonControlDriverFactory()
    let snapshot = try ControlSnapshotFixture().snapshot(
      tunnelNames: ["synthetic-tunnel-first", "synthetic-tunnel-second"],
      selectedEncodedTunnelIndex: 1
    )
    let lease = try await activeNCRouteLease(factory, snapshot: snapshot)
    #expect(factory.driver.observedStartTunnelCounts == [2])

    let enableTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    #expect(factory.driver.observations[1].tunnelName == "synthetic-tunnel-second")
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 1)
    #expect((await enableTask.value).outcome == .transportAcknowledged)

    let disableTask = Task {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    #expect(factory.driver.observations[2].tunnelName == "synthetic-tunnel-second")
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 2)
    #expect((await disableTask.value).outcome == .transportAcknowledged)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 3)
  }

  @Test func malformedAndDuplicateRouteRepliesDoNotAcknowledgeOrBlockStop() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)

    let toggleTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    let malformed = ncRouteReply(success: true)
    xpc_dictionary_set_bool(malformed, "extra", true)
    factory.driver.emitReplyDictionary(malformed, at: 1)
    let toggle = await toggleTask.value

    #expect(toggle.outcome == .unexpectedReplyPayload)
    #expect(!toggle.transportAcknowledged)
    #expect(toggle.connectionRetained)
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 1)

    let stopTask = Task { await lease.stop(timeoutMilliseconds: 500) }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    factory.driver.emitReply(.emptyAcknowledgement, at: 2)
    #expect((await stopTask.value).outcome == .transportAcknowledged)
    #expect(factory.callCount == 1)
  }

  @Test func connectionInvalidDuringRouteToggleClosesRetainedSession() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)

    let toggleTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.invalidateSession()
    let toggle = await toggleTask.value

    #expect(toggle.outcome == .connectionInvalid)
    #expect(toggle.requestSent)
    #expect(!toggle.transportAcknowledged)
    #expect(!toggle.connectionRetained)
    #expect(toggle.connectionCancelRequested)
    #expect(!toggle.replyUnavailableObserved)
    #expect(toggle.completionSource == .connectionTerminal)
    let stop = await lease.stop(timeoutMilliseconds: 500)
    #expect(stop.outcome == .leaseClosed)
    #expect(!stop.requestSent)
    #expect(factory.driver.submitCount == 2)
    #expect(factory.driver.cancelCount == 1)
  }

  @Test func falseRouteReplyIsHelperRejectionAndLeaseStillStops() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReplyDictionary(ncRouteReply(success: false), at: 1)
    let receipt = await task.value

    #expect(receipt.outcome == .helperRejected)
    #expect(!receipt.transportAcknowledged)
    #expect(receipt.connectionRetained)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func routeToggleTimeoutRetainsLeaseForStop() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let receipt = await lease.setSelectedNCEnabled(
      true,
      timeoutMilliseconds: 10,
      peerGenerationValidator: { true }
    )

    #expect(receipt.outcome == .timeout)
    #expect(receipt.requestSent)
    #expect(receipt.connectionRetained)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func routeToggleCancellationRetainsLeaseForStop() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    task.cancel()
    let receipt = await task.value

    #expect(receipt.outcome == .cancelled)
    #expect(receipt.requestSent)
    #expect(receipt.connectionRetained)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func lateReplyFromTimedOutAttemptCannotCompleteNextToggle() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let first = await lease.setSelectedNCEnabled(
      true,
      timeoutMilliseconds: 10,
      peerGenerationValidator: { true }
    )
    #expect(first.outcome == .timeout)
    #expect(factory.driver.submitCount == 2)

    let secondTask = Task {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { false }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 1)
    try await Task.sleep(for: .milliseconds(20))
    #expect(lease.observation.replySignatures.isEmpty)

    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 2)
    let second = await secondTask.value
    #expect(second.outcome == .peerGenerationMismatch)
    #expect(!second.transportAcknowledged)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 3)
  }

  @Test func staleAsyncValidationCannotCompleteNextToggle() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let validation = RouteToggleValidationGate()
    let firstTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { await validation.wait() }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 1)
    #expect(await waitForControl { validation.entered })
    firstTask.cancel()
    #expect((await firstTask.value).outcome == .cancelled)

    let secondTask = Task {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { false }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    validation.release()
    try await Task.sleep(for: .milliseconds(20))
    #expect(lease.observation.replySignatures.isEmpty)

    factory.driver.emitReplyDictionary(ncRouteReply(success: true), at: 2)
    let second = await secondTask.value
    #expect(second.outcome == .peerGenerationMismatch)
    #expect(!second.transportAcknowledged)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 3)
  }

  @Test func ordinaryConnectionTrueAcknowledgementWinsAndRetainsLease() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let validation = RouteToggleValidationGate()
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { await validation.wait() }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    #expect(await waitForControl { validation.entered })
    factory.driver.emitReplyDictionary(ncRouteReply(success: false), at: 1)
    validation.release()
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.peerGenerationValidated)
    #expect(receipt.connectionRetained)
    #expect(receipt.incomingEventSignatures == ["1:connection:updown_nc_success:bool"])
    factory.driver.emitReply(.replyUnavailable, at: 1)
    try await Task.sleep(for: .milliseconds(20))
    #expect(factory.driver.cancelCount == 0)
    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func ordinaryConnectionFalseAcknowledgementRejectsAndRetainsLease() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitConnectionDictionary(ncRouteReply(success: false))
    let receipt = await task.value

    #expect(receipt.outcome == .helperRejected)
    #expect(!receipt.peerGenerationValidated)
    #expect(receipt.connectionRetained)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func ordinaryAcknowledgementsStayFIFOAcrossTimedOutAttempt() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let firstTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 10,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.replyUnavailable, at: 1)
    let first = await firstTask.value
    #expect(first.outcome == .timeout)
    #expect(first.replyUnavailableObserved)
    #expect(first.completionSource == .timeout)

    let validation = RouteToggleValidationGate()
    let secondTask = Task {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { await validation.wait() }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    factory.driver.emitReply(.replyUnavailable, at: 1)
    try await Task.sleep(for: .milliseconds(20))
    #expect(!validation.entered)

    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    try await Task.sleep(for: .milliseconds(20))
    #expect(!validation.entered)

    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    #expect(await waitForControl { validation.entered })
    validation.release()
    let second = await secondTask.value
    #expect(second.outcome == .transportAcknowledged)
    #expect(second.connectionRetained)
    #expect(!second.replyUnavailableObserved)
    #expect(second.completionSource == .ordinaryConnection)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 3)
  }

  @Test func sequentialOrdinaryEnableAndDisableUseFIFOAttempts() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)

    let enableTask = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    #expect((await enableTask.value).outcome == .transportAcknowledged)

    let disableTask = Task {
      await lease.setSelectedNCEnabled(
        false,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 3 })
    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    #expect((await disableTask.value).outcome == .transportAcknowledged)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 3)
  }

  @Test func replyUnavailableThenOrdinaryRouteAcknowledgesAndRetainsLease() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })

    factory.driver.emitReply(.replyUnavailable, at: 1)
    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.peerGenerationValidated)
    #expect(receipt.replyUnavailableObserved)
    #expect(receipt.completionSource == .replyUnavailableThenOrdinary)
    #expect(receipt.connectionRetained)
    #expect(factory.driver.cancelCount == 0)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func replyUnavailableDuringHeldRouteValidatorDoesNotOverrideResult() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let validation = RouteToggleValidationGate()
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { await validation.wait() }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitConnectionDictionary(ncRouteReply(success: true))
    #expect(await waitForControl { validation.entered })

    factory.driver.emitReply(.replyUnavailable, at: 1)
    try await Task.sleep(for: .milliseconds(20))
    #expect(factory.driver.cancelCount == 0)
    validation.release()
    let receipt = await task.value

    #expect(receipt.outcome == .transportAcknowledged)
    #expect(receipt.replyUnavailableObserved)
    #expect(receipt.completionSource == .ordinaryConnection)
    #expect(receipt.connectionRetained)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func replyUnavailableThenRouteTimeoutRetainsLeaseForStop() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 10,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    factory.driver.emitReply(.replyUnavailable, at: 1)
    let receipt = await task.value

    #expect(receipt.outcome == .timeout)
    #expect(receipt.replyUnavailableObserved)
    #expect(receipt.completionSource == .timeout)
    #expect(receipt.connectionRetained)
    #expect(factory.driver.cancelCount == 0)
    try await stopNCRouteLease(lease, factory: factory, replyIndex: 2)
  }

  @Test func malformedOrdinaryConnectionAcknowledgementFailsClosed() async throws {
    let factory = CharonControlDriverFactory()
    let lease = try await activeNCRouteLease(factory)
    let task = Task {
      await lease.setSelectedNCEnabled(
        true,
        timeoutMilliseconds: 500,
        peerGenerationValidator: { true }
      )
    }
    #expect(await waitForControl { factory.driver.submitCount == 2 })
    let malformed = ncRouteReply(success: true)
    xpc_dictionary_set_bool(malformed, "extra", true)

    factory.driver.emitConnectionDictionary(malformed)
    let receipt = await task.value

    #expect(receipt.outcome == .unexpectedConnectionEvent)
    #expect(!receipt.connectionRetained)
    #expect(receipt.connectionCancelRequested)
    #expect((await lease.stop(timeoutMilliseconds: 500)).outcome == .leaseClosed)
  }

}

private final class RouteToggleValidationGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Bool, Never>?
  private var didEnter = false

  var entered: Bool { lock.withLock { didEnter } }

  func wait() async -> Bool {
    await withCheckedContinuation { continuation in
      lock.withLock {
        didEnter = true
        self.continuation = continuation
      }
    }
  }

  func release() {
    let continuation = lock.withLock {
      defer { self.continuation = nil }
      return self.continuation
    }
    continuation?.resume(returning: true)
  }
}

private func activeNCRouteLease(
  _ factory: CharonControlDriverFactory
) async throws -> VendorCharonControlLease {
  try await activeNCRouteLease(
    factory,
    snapshot: ControlSnapshotFixture().snapshot()
  )
}

private func activeNCRouteLease(
  _ factory: CharonControlDriverFactory,
  snapshot: VendorCharonStartSnapshot
) async throws -> VendorCharonControlLease {
  let task = Task {
    await controlTransport(factory).start(
      snapshot: snapshot,
      timeoutMilliseconds: 500,
      peerGenerationValidator: { true }
    )
  }
  #expect(await waitForControl { factory.driver.submitCount == 1 })
  factory.driver.emitReply(.emptyAcknowledgement, at: 0)
  return try #require((await task.value).lease)
}

private func stopNCRouteLease(
  _ lease: VendorCharonControlLease,
  factory: CharonControlDriverFactory,
  replyIndex: Int
) async throws {
  let task = Task { await lease.stop(timeoutMilliseconds: 500) }
  #expect(await waitForControl { factory.driver.submitCount > replyIndex })
  factory.driver.emitReply(.emptyAcknowledgement, at: replyIndex)
  #expect((await task.value).outcome == .transportAcknowledged)
}

private func ncRouteReply(success: Bool) -> xpc_object_t {
  let reply = xpc_dictionary_create(nil, nil, 0)
  xpc_dictionary_set_bool(reply, "updown_nc_success", success)
  return reply
}
