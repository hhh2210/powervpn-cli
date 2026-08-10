import Foundation
import Security

struct TLSPeerCertificateChain: Equatable, Sendable {
  static let maximumCertificateCount = 16
  static let maximumCertificateBytes = 65_536

  let certificateDER: [Data]
}

enum TLSPeerChainCaptureError: Error, Equatable, Sendable {
  case metadataUnavailable
  case invalidChain
  case invalidCertificate
}

protocol TLSPeerChainCapturing: Sendable {
  func capture(
    from metadata: sec_protocol_metadata_t
  ) -> Result<TLSPeerCertificateChain, TLSPeerChainCaptureError>
}

struct MetadataTLSPeerChainCapturer: TLSPeerChainCapturing {
  func capture(
    from metadata: sec_protocol_metadata_t
  ) -> Result<TLSPeerCertificateChain, TLSPeerChainCaptureError> {
    let accumulator = TLSPeerChainAccumulator()
    let accessible = sec_protocol_metadata_access_peer_certificate_chain(metadata) {
      certificate in
      accumulator.append(certificate)
    }
    return accumulator.finish(metadataAccessible: accessible)
  }
}

final class TLSPeerChainAccumulator: @unchecked Sendable {
  typealias CertificateCopy = @Sendable (sec_certificate_t) -> Data?

  private let lock = NSLock()
  private let certificateCopy: CertificateCopy
  private var nextIndex = 0
  private var indexedDER: [Int: Data] = [:]
  private var failure: TLSPeerChainCaptureError?

  init(certificateCopy: @escaping CertificateCopy = TLSPeerChainAccumulator.copyDER) {
    self.certificateCopy = certificateCopy
  }

  func append(_ certificate: sec_certificate_t) {
    let index = lock.withLock { () -> Int? in
      guard failure == nil else { return nil }
      guard nextIndex < TLSPeerCertificateChain.maximumCertificateCount else {
        failure = .invalidChain
        return nil
      }
      defer { nextIndex += 1 }
      return nextIndex
    }
    guard let index, let der = certificateCopy(certificate),
      !der.isEmpty,
      der.count <= TLSPeerCertificateChain.maximumCertificateBytes
    else {
      lock.withLock {
        if failure == nil { failure = .invalidCertificate }
      }
      return
    }
    lock.withLock {
      guard failure == nil else { return }
      indexedDER[index] = der
    }
  }

  func finish(
    metadataAccessible: Bool
  ) -> Result<TLSPeerCertificateChain, TLSPeerChainCaptureError> {
    lock.withLock {
      guard metadataAccessible else { return .failure(.metadataUnavailable) }
      if let failure { return .failure(failure) }
      guard nextIndex > 0, indexedDER.count == nextIndex else {
        return .failure(.invalidChain)
      }
      let ordered = (0..<nextIndex).compactMap { indexedDER[$0] }
      guard ordered.count == nextIndex else { return .failure(.invalidChain) }
      return .success(TLSPeerCertificateChain(certificateDER: ordered))
    }
  }

  private static func copyDER(_ certificate: sec_certificate_t) -> Data? {
    let retained = sec_certificate_copy_ref(certificate).takeRetainedValue()
    let source = SecCertificateCopyData(retained) as Data
    return source.withUnsafeBytes { Data($0) }
  }
}
