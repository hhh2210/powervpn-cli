import PowerVPNCore
import PowerVPNPortal

enum ProductM2NetworkGateError: Error {
  case snapshotRejected
  case selectedRouteCoverageRejected
}

extension ProductM2ConnectOnceCoordinator {
  func selectedRouteMatcher(
    snapshot: AuthenticatedPortalSnapshot,
    handle: String,
    requiredTargetIPv4: UInt32
  ) throws -> VendorCharonSelectedRouteMatcher {
    var matcher: VendorCharonSelectedRouteMatcher?
    do {
      try AuthenticatedPortalSnapshotMapper.withValidatedStartSnapshot(
        snapshot,
        handle: handle
      ) { startSnapshot in
        matcher = try startSnapshot.makeSelectedRouteMatcher(
          requiredTargetIPv4: requiredTargetIPv4
        )
      }
    } catch let error as VendorCharonSelectedRouteMatcherError {
      guard error == .requiredTargetNotCovered else {
        throw ProductM2NetworkGateError.snapshotRejected
      }
      throw ProductM2NetworkGateError.selectedRouteCoverageRejected
    } catch {
      throw ProductM2NetworkGateError.snapshotRejected
    }
    guard let matcher else { throw ProductM2NetworkGateError.snapshotRejected }
    return matcher
  }
}
