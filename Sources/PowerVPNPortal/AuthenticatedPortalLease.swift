import Foundation

package enum PortalLeaseLogoutStatus: String, Sendable {
  case accepted
  case rejected
  case timedOut = "timed_out"
  case cancelled
  case alreadyClosed = "already_closed"
}

package enum PortalSnapshotAcquisitionResult: Sendable {
  case acquired(AuthenticatedPortalLease)
  case rejected(PortalLoginReport)
}

/// Package-scoped owner for one authenticated Portal generation. Explicit
/// close erases the snapshot's app-owned resource storage; it cannot erase
/// copies deliberately created by another package target.
package actor AuthenticatedPortalLease {
  package nonisolated let snapshot: AuthenticatedPortalSnapshot

  private let factory: PortalRequestFactory
  private let transport: any PortalTransporting
  private let logoutBounder: any PortalLogoutBounding
  private var closed = false

  init(
    snapshot: AuthenticatedPortalSnapshot,
    factory: PortalRequestFactory,
    transport: any PortalTransporting,
    logoutBounder: any PortalLogoutBounding
  ) {
    self.snapshot = snapshot
    self.factory = factory
    self.transport = transport
    self.logoutBounder = logoutBounder
  }

  package func logoutAndErase() async -> PortalLeaseLogoutStatus {
    guard !closed else { return .alreadyClosed }
    closed = true
    snapshot.erase()
    defer {
      factory.eraseSession()
      transport.cancel()
    }

    let request: PortalHTTPRequest
    do {
      request = try factory.makeLogoutRequest()
    } catch {
      return .rejected
    }
    let observation = PortalLeaseLogoutObservation()
    let transport = self.transport
    let finished = await logoutBounder.run {
      do {
        let response = try await transport.perform(request)
        request.erase()
        let accepted = response.statusCode == 200
        response.erase()
        observation.complete(accepted ? .accepted : .rejected)
      } catch {
        request.erase()
        if error is CancellationError
          || (error as? PortalTransportError) == .cancelled
        {
          observation.complete(.cancelled)
        } else {
          observation.complete(.rejected)
        }
      }
    }
    guard finished else {
      request.erase()
      return .timedOut
    }
    return observation.status ?? .rejected
  }

  deinit {
    transport.cancel()
    snapshot.erase()
    factory.eraseSession()
  }
}

private final class PortalLeaseLogoutObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var result: PortalLeaseLogoutStatus?

  func complete(_ status: PortalLeaseLogoutStatus) {
    lock.withLock {
      if result == nil { result = status }
    }
  }

  var status: PortalLeaseLogoutStatus? { lock.withLock { result } }
}
