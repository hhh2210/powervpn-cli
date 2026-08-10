import CryptoKit
import Foundation

/// Holds per-live-window tokenization state. Reuse one instance for preflight
/// A/B and after-cleanup captures; never serialize it.
package final class NetworkCleanupCaptureWindow: @unchecked Sendable {
  private let key: SymmetricKey

  package init() {
    key = SymmetricKey(size: .bits256)
  }

  init(keyData: Data) {
    key = SymmetricKey(data: keyData)
  }

  func interfaceToken(_ name: String) -> Data {
    token(domain: "interface", record: name)
  }

  func vendorProcessToken(_ record: String) -> Data {
    token(domain: "vendor-process", record: record)
  }

  private func token(domain: String, record: String) -> Data {
    Data(
      HMAC<SHA256>.authenticationCode(
        for: Data("powervpn.network-window.v1\0\(domain)\0\(record)".utf8),
        using: key
      ))
  }
}
