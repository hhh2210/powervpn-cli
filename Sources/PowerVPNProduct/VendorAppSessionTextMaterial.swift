import PowerVPNCore
import PowerVPNPortal

struct VendorAppSessionText: VendorCharonStartTextMaterial {
  let bytes: SecureBytes

  var byteCount: Int { bytes.count }

  func withUnsafeUTF8Bytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try bytes.withUnsafeBytes(body)
  }
}
