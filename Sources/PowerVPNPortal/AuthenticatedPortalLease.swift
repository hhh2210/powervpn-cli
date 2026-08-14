import Foundation

package enum PortalLeaseLogoutStatus: String, Sendable {
  case accepted
  case rejected
  case timedOut = "timed_out"
  case cancelled
  case alreadyClosed = "already_closed"
}

/// Value-free class of a rejected logout: whether the request could not be
/// constructed, the transport failed, or the remote exchange completed.
///
/// Official-contract context (PowerVPN 3.2.1 (24572) static dossier,
/// 2026-08-14, `-[VSGAuthManager logout]` `0x1000a6810`): the official
/// completion block (`0x1000a6a80`) never reads its `NSError` slot or the
/// parsed object — it deletes every `VSG_SESSIONID` cookie
/// (`0x1000a6af1`–`0x1000a6cc0`) and reports literal `0` to the delegate
/// (`0x1000a6d7a`–`0x1000a6def`). A completed exchange is therefore
/// officially non-failing regardless of HTTP status. Native acceptance stays
/// exactly-200 (a separate compatibility decision); local erasure is
/// unconditional either way.
package enum PortalLeaseLogoutFailureClass: String, Equatable, Sendable {
  case requestConstructionFailed = "request_construction_failed"
  case transportFailed = "transport_failed"
  case completedRemoteExchange = "completed_remote_exchange"
}

package struct PortalLeaseLogoutResult: Equatable, Sendable {
  package let status: PortalLeaseLogoutStatus
  /// Present only when `status == .rejected`.
  package let failureClass: PortalLeaseLogoutFailureClass?

  package init(
    status: PortalLeaseLogoutStatus,
    failureClass: PortalLeaseLogoutFailureClass? = nil
  ) {
    self.status = status
    self.failureClass = failureClass
  }
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

  package func logoutAndErase() async -> PortalLeaseLogoutResult {
    guard !closed else { return PortalLeaseLogoutResult(status: .alreadyClosed) }
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
      return PortalLeaseLogoutResult(
        status: .rejected,
        failureClass: .requestConstructionFailed
      )
    }
    let observation = PortalLeaseLogoutObservation()
    let transport = self.transport
    let finished = await logoutBounder.run {
      do {
        let response = try await transport.perform(request)
        request.erase()
        let accepted = response.statusCode == 200
        response.erase()
        observation.complete(
          accepted
            ? PortalLeaseLogoutResult(status: .accepted)
            : PortalLeaseLogoutResult(
              status: .rejected,
              failureClass: .completedRemoteExchange
            )
        )
      } catch {
        request.erase()
        if error is CancellationError
          || (error as? PortalTransportError) == .cancelled
        {
          observation.complete(PortalLeaseLogoutResult(status: .cancelled))
        } else {
          observation.complete(
            PortalLeaseLogoutResult(
              status: .rejected,
              failureClass: .transportFailed
            )
          )
        }
      }
    }
    guard finished else {
      request.erase()
      return PortalLeaseLogoutResult(status: .timedOut)
    }
    return observation.logoutResult
      ?? PortalLeaseLogoutResult(
        status: .rejected,
        failureClass: .requestConstructionFailed
      )
  }

  deinit {
    transport.cancel()
    snapshot.erase()
    factory.eraseSession()
  }
}

private final class PortalLeaseLogoutObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var result: PortalLeaseLogoutResult?

  func complete(_ result: PortalLeaseLogoutResult) {
    lock.withLock {
      if self.result == nil { self.result = result }
    }
  }

  var logoutResult: PortalLeaseLogoutResult? { lock.withLock { result } }
}
