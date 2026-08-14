import Foundation

@testable import PowerVPNPortal
@testable import PowerVPNProduct

final class PortalDryRunTransportSpy: @unchecked Sendable, PortalTransporting {
  private let lock = NSLock()
  private let statusCode: Int
  private let thrownError: PortalTransportError?
  private var requests = 0
  private var cancellations = 0

  init(statusCode: Int = 200, thrownError: PortalTransportError? = nil) {
    self.statusCode = statusCode
    self.thrownError = thrownError
  }

  func perform(_ request: PortalHTTPRequest) async throws -> PortalHTTPResponse {
    guard request.begin() else { throw PortalTransportError.invalidRequest }
    lock.withLock { requests += 1 }
    request.erase()
    if let thrownError {
      throw thrownError
    }
    return PortalHTTPResponse(
      statusCode: statusCode,
      body: try SecureBytes(copying: [])
    )
  }

  func cancel() {
    lock.withLock { cancellations += 1 }
  }

  var requestCount: Int { lock.withLock { requests } }
  var cancellationCount: Int { lock.withLock { cancellations } }
}

struct PortalDryRunImmediateLogoutBounder: PortalLogoutBounding {
  func run(_ operation: @escaping @Sendable () async -> Void) async -> Bool {
    await operation()
    return true
  }
}

struct PortalDryRunLeaseFixture {
  let snapshotFixture: AuthenticatedSnapshotFixture
  let lease: AuthenticatedPortalLease
  let transport: PortalDryRunTransportSpy

  func erase() {
    snapshotFixture.erase()
  }

  /// Erases the factory session so the logout request cannot be constructed.
  func eraseFactorySession() {
    snapshotFixture.factory.eraseSession()
  }
}

func portalDryRunLease(
  resourceXML: String,
  logoutStatusCode: Int = 200,
  logoutTransportError: PortalTransportError? = nil
) throws -> PortalDryRunLeaseFixture {
  let fixture = try authenticatedSnapshot(resourceXML: resourceXML)
  let transport = PortalDryRunTransportSpy(
    statusCode: logoutStatusCode,
    thrownError: logoutTransportError
  )
  return PortalDryRunLeaseFixture(
    snapshotFixture: fixture,
    lease: AuthenticatedPortalLease(
      snapshot: fixture.snapshot,
      factory: fixture.factory,
      transport: transport,
      logoutBounder: PortalDryRunImmediateLogoutBounder()
    ),
    transport: transport
  )
}

actor PortalDryRunAcquisitionGate {
  private let result: PortalSnapshotAcquisitionResult
  private var entered = false
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseContinuation: CheckedContinuation<Void, Never>?

  init(result: PortalSnapshotAcquisitionResult) {
    self.result = result
  }

  func acquire() async -> PortalSnapshotAcquisitionResult {
    entered = true
    for waiter in enteredWaiters {
      waiter.resume()
    }
    enteredWaiters.removeAll()
    await withCheckedContinuation { releaseContinuation = $0 }
    return result
  }

  func waitUntilEntered() async {
    guard !entered else { return }
    await withCheckedContinuation { enteredWaiters.append($0) }
  }

  func release() {
    releaseContinuation?.resume()
    releaseContinuation = nil
  }
}
