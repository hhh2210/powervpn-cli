import Foundation
import Testing

@testable import PowerVPNTLSEvidence

@Suite struct X509SPKIExtractorTests {
  // Expected values were produced independently with:
  // openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER |
  // shasum -a 256
  @Test(
    arguments: [
      (
        "rsa-cert",
        "274e8cf9b4d2876c7f62be79ad49de327096c65dbd63d24c16886123985c42b9",
        "c185e9fb0d89e34478d4622694489592f54458eb7560b0914f13c1f0c01fec19"
      ),
      (
        "ec-cert",
        "6e30d009f3a7d6cde66c692bfffb91f2c8861a918ea6950f527147381f45f3c8",
        "15c9842af15a8c819ac0941d560485b708d8d1b3642f0c329def9fb9fdefcedc"
      ),
    ]
  )
  func rsaAndECDifferentialVectors(
    fixture: String,
    certificateSHA256: String,
    spkiSHA256: String
  ) throws {
    let certificate = try fixtureDER(fixture)
    #expect(TLSTrustSnapshotBuilder.sha256Hex(certificate) == certificateSHA256)
    let spki = try X509SPKIExtractor.extract(from: certificate)
    #expect(TLSTrustSnapshotBuilder.sha256Hex(spki) == spkiSHA256)
    #expect(spki.first == 0x30)
  }

  @Test func malformedAndUnboundedDERFailsClosed() {
    let invalid = [
      Data(),
      Data([0x30, 0x80, 0x00, 0x00]),
      Data([0x30, 0x81, 0x01, 0x00]),
      Data([0x31, 0x00]),
      Data(repeating: 0, count: X509SPKIExtractor.maximumCertificateBytes + 1),
    ]
    for value in invalid {
      #expect(throws: X509SPKIError.self) {
        _ = try X509SPKIExtractor.extract(from: value)
      }
    }
  }

  @Test func everyTruncationOfValidCertificateFailsClosed() throws {
    let certificate = try fixtureDER("ec-cert")
    for length in 0..<certificate.count {
      #expect(throws: X509SPKIError.self) {
        _ = try X509SPKIExtractor.extract(from: certificate.prefix(length))
      }
    }
  }
}

func fixtureDER(_ name: String) throws -> Data {
  let url = try #require(
    Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures")
  )
  let pem = try String(contentsOf: url, encoding: .utf8)
  let base64 = pem.split(separator: "\n")
    .filter { !$0.hasPrefix("-----") }
    .joined()
  return try #require(Data(base64Encoded: base64))
}
