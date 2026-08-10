import Foundation

@testable import PowerVPNTLSEvidence

enum TLSClientHelloParser {
  static func completeRecordLength(_ data: Data) -> Int? {
    guard data.count >= 5 else { return nil }
    let bytes = [UInt8](data.prefix(5))
    guard bytes[0] == 22 else { return 0 }
    return 5 + (Int(bytes[3]) << 8) + Int(bytes[4])
  }

  static func serverNameExtensionCount(_ data: Data) -> Int? {
    let bytes = [UInt8](data)
    guard let recordEnd = completeRecordLength(data), recordEnd <= bytes.count,
      recordEnd >= 9, bytes[5] == 1
    else { return nil }
    let handshakeLength = integer24(bytes, at: 6)
    guard handshakeLength + 9 <= recordEnd else { return nil }
    var cursor = 9 + 2 + 32
    guard let sessionLength = byte(bytes, at: cursor) else { return nil }
    cursor += 1 + Int(sessionLength)
    guard let cipherLength = integer16(bytes, at: cursor) else { return nil }
    cursor += 2 + cipherLength
    guard let compressionLength = byte(bytes, at: cursor) else { return nil }
    cursor += 1 + Int(compressionLength)
    if cursor == 9 + handshakeLength { return 0 }
    guard let extensionsLength = integer16(bytes, at: cursor) else { return nil }
    cursor += 2
    let extensionsEnd = cursor + extensionsLength
    guard extensionsEnd <= 9 + handshakeLength, extensionsEnd <= bytes.count else { return nil }
    var count = 0
    while cursor < extensionsEnd {
      guard let type = integer16(bytes, at: cursor),
        let length = integer16(bytes, at: cursor + 2),
        cursor + 4 + length <= extensionsEnd
      else { return nil }
      if type == 0 { count += 1 }
      cursor += 4 + length
    }
    return cursor == extensionsEnd ? count : nil
  }

  private static func byte(_ bytes: [UInt8], at index: Int) -> UInt8? {
    index < bytes.count ? bytes[index] : nil
  }

  private static func integer16(_ bytes: [UInt8], at index: Int) -> Int? {
    guard index + 1 < bytes.count else { return nil }
    return Int(bytes[index]) << 8 | Int(bytes[index + 1])
  }

  private static func integer24(_ bytes: [UInt8], at index: Int) -> Int {
    Int(bytes[index]) << 16 | Int(bytes[index + 1]) << 8 | Int(bytes[index + 2])
  }
}

final class LocalTLSLatch<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var stored: Value?

  func resolve(_ value: Value) {
    let shouldSignal = lock.withLock {
      guard stored == nil else { return false }
      stored = value
      return true
    }
    if shouldSignal { semaphore.signal() }
  }

  func wait(timeout: DispatchTimeInterval) -> Value? {
    guard semaphore.wait(timeout: .now() + timeout) == .success else { return nil }
    return lock.withLock { stored }
  }
}

final class LocalTLSLocked<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: Value

  init(_ value: Value) { stored = value }

  func set(_ value: Value) { lock.withLock { stored = value } }
  func value() -> Value { lock.withLock { stored } }
}

final class LocalTLSVerificationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var callbacks = 0
  private var rejectionCompletions = 0
  private var chainLength = 0
  private var leafSHA256: String?
  private var ready = false

  func recordCallback() { lock.withLock { callbacks += 1 } }
  func recordRejectionCompletion() { lock.withLock { rejectionCompletions += 1 } }
  func recordChain(_ chain: TLSPeerCertificateChain) {
    lock.withLock {
      chainLength = chain.certificateDER.count
      leafSHA256 = chain.certificateDER.first.map(TLSTrustSnapshotBuilder.sha256Hex)
    }
  }
  func recordReady() { lock.withLock { ready = true } }
  func snapshot() -> (
    callbackCount: Int,
    completionCount: Int,
    chainLength: Int,
    leafSHA256: String?,
    ready: Bool
  ) {
    lock.withLock {
      (callbacks, rejectionCompletions, chainLength, leafSHA256, ready)
    }
  }
}
