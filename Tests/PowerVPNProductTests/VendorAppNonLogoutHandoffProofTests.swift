import Darwin
import Foundation
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppNonLogoutHandoffProofTests {
  @Test func completeProofIsValueFreeAndBoundToOneCursorGeneration() throws {
    let cursor = try syntheticCursor(inode: 101)
    let proof = try syntheticProof(for: cursor)
    #expect(proof.isStructurallyValid)
    #expect(proof.isBound(to: cursor))
    #expect(!proof.isBound(to: try syntheticCursor(inode: 102)))

    let encoded = try JSONEncoder().encode(proof)
    let text = String(decoding: encoded, as: UTF8.self)
    for forbidden in ["synthetic-session", "synthetic-psk", "login21", "gateway"] {
      #expect(!text.contains(forbidden))
    }
  }

  @Test func incompleteCleanupCannotBecomeACursorProof() throws {
    let cursor = try syntheticCursor(inode: 111)
    let complete = try syntheticProof(for: cursor)
    var object = try #require(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(complete))
        as? [String: Any]
    )
    var cleanup = try #require(object["cleanup"] as? [String: Any])
    cleanup["dnsRestored"] = false
    object["cleanup"] = cleanup
    let tampered = try JSONDecoder().decode(
      VendorAppNonLogoutHandoffProof.self,
      from: JSONSerialization.data(withJSONObject: object)
    )

    #expect(!tampered.isStructurallyValid)
    #expect(throws: VendorAppOnboardingCursorError.self) {
      _ = try cursor.proving(tampered)
    }
  }

  private func syntheticCursor(inode: UInt64) throws -> VendorAppOnboardingCursor {
    let timestamp = try VendorAppCursorTimestamp(seconds: 1_723_000_000, nanoseconds: 123)
    return VendorAppOnboardingCursor(
      schema: VendorAppOnboardingCursor.schemaVersion,
      device: 7,
      inode: inode,
      size: 1_024,
      ownerUID: 0,
      mode: UInt32(S_IFREG | S_IRUSR | S_IWUSR),
      modificationTime: timestamp,
      changeTime: timestamp,
      capturedAt: timestamp
    )
  }

  private func syntheticProof(
    for cursor: VendorAppOnboardingCursor
  ) throws -> VendorAppNonLogoutHandoffProof {
    VendorAppNonLogoutHandoffProof(
      cleanup: VendorAppNonLogoutHandoffCleanupProof(
        complete: true,
        defaultRouteRestored: true,
        dnsRestored: true,
        interfacesRestored: true,
        utunRestored: true,
        persistentRoutesRestored: true,
        surgeStateRestored: true,
        vendorProcessesAbsent: true,
        helperInactive: true,
        structuralRouteTablesEqual: true
      ),
      finalSourceSeal: VendorAppSessionSourceSeal(
        device: cursor.device,
        inode: cursor.inode,
        size: Int64(cursor.size + 512),
        ownerUID: cursor.ownerUID,
        mode: cursor.mode,
        modificationSeconds: cursor.modificationTime.seconds + 1,
        modificationNanoseconds: 0,
        changeSeconds: cursor.changeTime.seconds + 1,
        changeNanoseconds: 0
      ),
      finalHelperRuns: 21,
      createdAt: try VendorAppCursorTimestamp(
        seconds: cursor.capturedAt.seconds + 1,
        nanoseconds: 0
      )
    )
  }
}
