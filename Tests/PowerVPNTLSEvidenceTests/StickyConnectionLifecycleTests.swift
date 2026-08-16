import Foundation
import Network
import Testing

@testable import PowerVPNTLSEvidence

@Suite struct StickyConnectionLifecycleTests {
  @Test func cancelBeforeStartIsSticky() {
    let connection = FakeTLSNetworkConnection()
    let factoryCalls = LockedCounter()
    let events = EventRecorder()
    let source = NetworkTLSTrustSource { _, _, _ in
      factoryCalls.increment()
      return connection
    }

    source.cancel()
    source.start { events.record($0) }

    #expect(factoryCalls.value == 0)
    #expect(connection.startCount == 0)
    #expect(connection.cancelCount == 0)
    #expect(events.values == [.unavailable])
  }

  @Test func cancelDuringConstructionDisposesWithoutStarting() {
    let connection = FakeTLSNetworkConnection()
    let barrier = ConstructionBarrier(connection: connection)
    let events = EventRecorder()
    let source = NetworkTLSTrustSource(
      host: "192.0.2.1",
      port: 4_443,
      connectionFactory: barrier.makeConnection
    )
    let startReturned = DispatchSemaphore(value: 0)

    DispatchQueue.global().async {
      source.start { events.record($0) }
      startReturned.signal()
    }

    #expect(barrier.waitUntilEntered())
    source.cancel()
    barrier.allowPublication()
    #expect(startReturned.waitBounded())

    #expect(connection.startCount == 0)
    #expect(connection.cancelCount == 1)
    #expect(events.values.isEmpty)
    connection.emitLateState(.failed(.posix(.ECANCELED)))
    #expect(events.values.isEmpty)
    #expect(!source.progressSnapshot().transport.failedObserved)
  }

  @Test func startOnceCancelIsIdempotentAndLateCallbackIsIgnored() {
    let connection = FakeTLSNetworkConnection()
    let factoryCalls = LockedCounter()
    let primaryEvents = EventRecorder()
    let duplicateEvents = EventRecorder()
    let source = NetworkTLSTrustSource(
      host: "192.0.2.1",
      port: 4_443
    ) { _, _, _ in
      factoryCalls.increment()
      return connection
    }

    source.start { primaryEvents.record($0) }
    source.start { duplicateEvents.record($0) }

    #expect(factoryCalls.value == 1)
    #expect(connection.startCount == 1)
    #expect(duplicateEvents.values == [.unavailable])

    source.cancel()
    source.cancel()
    connection.emitLateState(.failed(.posix(.ECANCELED)))

    #expect(connection.cancelCount == 1)
    #expect(primaryEvents.values.isEmpty)
    #expect(!source.progressSnapshot().transport.failedObserved)
  }
}

private final class ConstructionBarrier: @unchecked Sendable {
  private let entered = DispatchSemaphore(value: 0)
  private let publication = DispatchSemaphore(value: 0)
  private let connection: FakeTLSNetworkConnection

  init(connection: FakeTLSNetworkConnection) { self.connection = connection }

  func makeConnection(
    _: NWEndpoint.Host,
    _: NWEndpoint.Port,
    _: NWParameters
  ) -> any TLSNetworkConnection {
    entered.signal()
    publication.wait()
    return connection
  }

  func waitUntilEntered() -> Bool { entered.waitBounded() }
  func allowPublication() { publication.signal() }
}

private final class FakeTLSNetworkConnection: TLSNetworkConnection, @unchecked Sendable {
  private let lock = NSLock()
  private var currentHandler: (@Sendable (NWConnection.State) -> Void)?
  private var retainedHandler: (@Sendable (NWConnection.State) -> Void)?
  private var starts = 0
  private var cancels = 0

  var startCount: Int { lock.withLock { starts } }
  var cancelCount: Int { lock.withLock { cancels } }

  func setEvidenceStateUpdateHandler(
    _ handler: (@Sendable (NWConnection.State) -> Void)?
  ) {
    lock.withLock {
      currentHandler = handler
      if let handler { retainedHandler = handler }
    }
  }

  func startEvidenceConnection(on _: DispatchQueue) {
    lock.withLock { starts += 1 }
  }

  func cancelEvidenceConnection() {
    lock.withLock {
      cancels += 1
      currentHandler = nil
    }
  }

  func emitLateState(_ state: NWConnection.State) {
    let callback = lock.withLock { retainedHandler }
    callback?(state)
  }
}

private final class EventRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [TLSTrustSourceEvent] = []

  var values: [TLSTrustSourceEvent] { lock.withLock { events } }
  func record(_ event: TLSTrustSourceEvent) { lock.withLock { events.append(event) } }
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0

  var value: Int { lock.withLock { count } }
  func increment() { lock.withLock { count += 1 } }
}

extension DispatchSemaphore {
  fileprivate func waitBounded() -> Bool {
    wait(timeout: .now() + .seconds(2)) == .success
  }
}
