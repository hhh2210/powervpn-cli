import CryptoKit
import Foundation
import Security

struct TLSTrustAssessment: Equatable, Sendable {
  let accepted: Bool
  let category: TLSTrustCategory
}

struct TLSTrustSnapshot: Equatable, Sendable {
  let orderedCertificateSHA256: [String]
  let leafSPKISHA256: String
  let sslTrust: TLSTrustAssessment
  let basicTrust: TLSTrustAssessment
}

enum TLSTrustSnapshotError: Error, Equatable, Sendable {
  case invalidChain
  case invalidSPKI
}

enum TLSTrustSnapshotBuilder {
  static func make(
    chain: TLSPeerCertificateChain,
    sslTrust: TLSTrustAssessment,
    basicTrust: TLSTrustAssessment
  ) -> Result<TLSTrustSnapshot, TLSTrustSnapshotError> {
    let certificateData = chain.certificateDER
    guard
      !certificateData.isEmpty,
      certificateData.count <= TLSPeerCertificateChain.maximumCertificateCount,
      certificateData.allSatisfy({
        !$0.isEmpty && $0.count <= TLSPeerCertificateChain.maximumCertificateBytes
      })
    else { return .failure(.invalidChain) }
    let spki: Data
    do {
      spki = try X509SPKIExtractor.extract(from: certificateData[0])
    } catch {
      return .failure(.invalidSPKI)
    }

    return .success(
      TLSTrustSnapshot(
        orderedCertificateSHA256: certificateData.map(sha256Hex),
        leafSPKISHA256: sha256Hex(spki),
        sslTrust: sslTrust,
        basicTrust: basicTrust
      ))
  }

  static func category(for error: CFError?) -> TLSTrustCategory {
    guard let error else { return .otherFailure }
    let code = (error as Error as NSError).code
    switch code {
    case Int(errSecHostNameMismatch): return .hostnameMismatch
    case Int(errSecCertificateExpired): return .expired
    case Int(errSecCertificateNotValidYet): return .notYetValid
    case Int(errSecCertificateRevoked): return .revoked
    case Int(errSecNotTrusted), Int(errSecCreateChainFailed): return .untrustedChain
    default: return .otherFailure
    }
  }

  static func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
}
