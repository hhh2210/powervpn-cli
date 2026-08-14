import CPortalCurl
import CryptoKit
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalFixedTOFUVerifierTests {
  @Test func productionProfileIsExactImmutableLocalMVPAuthority() throws {
    let verifier = try PortalFixedTOFUVerifier.currentMachine()
    let expectedOrigin = try PortalHTTPOrigin(host: "166.111.143.19", port: 4_443)

    #expect(verifier.profile.origin.absoluteString == "https://166.111.143.19:4443")
    #expect(verifier.origin == expectedOrigin)
    #expect(verifier.profile.selectionSemantics == .operatorApprovedFixedOrigin)
    #expect(PortalFixedTOFUVerifier.trustMode.rawValue == "operator_approved_tofu")
    #expect(!PortalFixedTOFUVerifier.releaseReady)
    #expect(
      PortalFixedTOFUVerifier.spkiSHA256Hex
        == "b7d82d5baa74d6bc8e45062475b54e81ebd2d2cabb6d01e0a0049677cd0eab54")
    #expect(
      PortalFixedTOFUVerifier.curlPinnedPublicKey
        == "sha256//t9gtW6p01ryORQYkdbVOgevS0sq7bQHgoASWd80Oq1Q=")
  }

  @Test func cAdapterSealsApprovedPinAndSavedLeaf() throws {
    let certificate = pvcurl_approved_leaf_certificate()
    let pointer = try #require(certificate.pointer)
    let data = Data(bytes: pointer, count: certificate.length)
    let certificateSHA256 = SHA256.hash(data: data)
      .map { String(format: "%02x", $0) }
      .joined()

    #expect(
      String(cString: pvcurl_approved_pinned_public_key())
        == PortalFixedTOFUVerifier.curlPinnedPublicKey)
    #expect(
      certificateSHA256
        == "c7060f659a92eee2a897790ef8dfc5f1b1c9098eba8196c6b316a23c2bb0954c")
  }

  @Test func curlPinAndHexDigestAreTheSameSPKIValue() throws {
    let encoded = PortalFixedTOFUVerifier.curlPinnedPublicKey
    let base64 = String(encoded.dropFirst("sha256//".count))
    let digest = try #require(Data(base64Encoded: base64))
    let hex = digest.map { String(format: "%02x", $0) }.joined()

    #expect(digest.count == 32)
    #expect(hex == PortalFixedTOFUVerifier.spkiSHA256Hex)
  }

  @Test func productionDiscoveryUsesFixedAuthorityWithoutInstalledDatabase() throws {
    let profile = try PortalLoginRuntimeDependencies.currentMachine.discoverProfile()
    let fixedProfile = try PortalFixedTOFUVerifier.currentMachine().profile
    #expect(profile == fixedProfile)
  }
}
