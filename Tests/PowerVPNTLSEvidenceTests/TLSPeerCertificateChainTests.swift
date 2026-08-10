import Foundation
import Security
import Testing

@testable import PowerVPNTLSEvidence

@Suite struct TLSPeerCertificateChainTests {
  @Test func preservesMetadataEnumerationOrderAndBounds() throws {
    let rsaDER = try fixtureDER("rsa-cert")
    let ecDER = try fixtureDER("ec-cert")
    let rsa = try protocolCertificate(rsaDER)
    let ec = try protocolCertificate(ecDER)
    let ordered = TLSPeerChainAccumulator()
    ordered.append(rsa)
    ordered.append(ec)

    let result = try ordered.finish(metadataAccessible: true).get()
    #expect(result.certificateDER == [rsaDER, ecDER])

    let maximum = TLSPeerChainAccumulator()
    for _ in 0..<TLSPeerCertificateChain.maximumCertificateCount { maximum.append(rsa) }
    #expect(try maximum.finish(metadataAccessible: true).get().certificateDER.count == 16)

    maximum.append(rsa)
    #expect(maximum.finish(metadataAccessible: true) == .failure(.invalidChain))
  }

  @Test func inaccessibleEmptyAndInvalidCopiesFailClosed() throws {
    let certificate = try protocolCertificate(fixtureDER("rsa-cert"))
    let inaccessible = TLSPeerChainAccumulator()
    inaccessible.append(certificate)
    #expect(
      inaccessible.finish(metadataAccessible: false) == .failure(.metadataUnavailable)
    )
    #expect(
      TLSPeerChainAccumulator().finish(metadataAccessible: true) == .failure(.invalidChain)
    )

    for copied in [
      Optional<Data>.none,
      Data(),
      Data(
        repeating: 0,
        count: TLSPeerCertificateChain.maximumCertificateBytes + 1
      ),
    ] {
      let accumulator = TLSPeerChainAccumulator { _ in copied }
      accumulator.append(certificate)
      #expect(
        accumulator.finish(metadataAccessible: true) == .failure(.invalidCertificate)
      )
    }
  }

  private func protocolCertificate(_ der: Data) throws -> sec_certificate_t {
    let certificate = try #require(SecCertificateCreateWithData(nil, der as CFData))
    return try #require(sec_certificate_create(certificate))
  }
}
