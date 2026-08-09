import Foundation

final class SecureBodyInputStream: InputStream, @unchecked Sendable {
  private let bytes: SecureBytes
  private var offset = 0
  private var status: Stream.Status = .notOpen
  private var failure: Error?

  init(bytes: SecureBytes) {
    self.bytes = bytes
    super.init(data: Data())
  }

  override func open() {
    if status == .notOpen { status = .open }
  }

  override func close() {
    status = .closed
  }

  override var streamStatus: Stream.Status { status }
  override var streamError: Error? { failure }
  override var hasBytesAvailable: Bool { status == .open && offset < bytes.count }

  override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength length: Int) -> Int {
    guard status == .open, length > 0 else { return status == .atEnd ? 0 : -1 }
    do {
      let copied = try bytes.withUnsafeBytes { source -> Int in
        let remaining = source.count - offset
        guard remaining > 0 else { return 0 }
        let copied = min(remaining, length)
        _ = memcpy(buffer, source.baseAddress!.advanced(by: offset), copied)
        offset += copied
        return copied
      }
      if copied == 0 { status = .atEnd }
      return copied
    } catch {
      failure = PortalTransportError.invalidRequest
      status = .error
      return -1
    }
  }

  override func getBuffer(
    _ buffer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    length: UnsafeMutablePointer<Int>
  ) -> Bool {
    false
  }
}
