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
    Data(HMAC<SHA256>.authenticationCode(for: Data(name.utf8), using: key))
  }
}
