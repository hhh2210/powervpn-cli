import Darwin
import Testing

@testable import PowerVPNProduct

@Suite struct VendorAppSessionProviderStateTests {
  @Test func availabilityAndReadinessRejectAndEraseStaleMaterial() throws {
    let availabilityMaterial = try vendorAppMaterial()
    let availabilityState = VendorAppSessionProviderState(
      cursor: try syntheticCursor(inode: 61),
      material: availabilityMaterial,
      sourceIsCurrent: { _ in false }
    )
    #expect(!availabilityState.isAvailable)
    #expect(availabilityMaterial.isErased)

    let readinessMaterial = try vendorAppMaterial()
    let readinessState = VendorAppSessionProviderState(
      cursor: try syntheticCursor(inode: 62),
      material: readinessMaterial,
      sourceIsCurrent: { _ in false }
    )
    #expect(readinessState.readinessCandidate() == nil)
    #expect(readinessMaterial.isErased)
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
}
