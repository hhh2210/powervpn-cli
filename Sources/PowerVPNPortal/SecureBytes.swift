import Darwin
import Foundation

public enum SecureBytesError: Error, Sendable {
  case allocationFailed
  case erased
}

/// An owned byte buffer whose storage is explicitly cleared before release.
///
/// Callers must not let a pointer obtained by `withUnsafeBytes` escape its
/// closure. Access and erasure are serialized across threads. The active
/// closure may reenter `count`, `withUnsafeBytes`, or `erase` on the same
/// thread. A reentrant erase zeroes storage immediately; the active pointer
/// then observes only zeroes and later access fails with `erased`.
public final class SecureBytes: @unchecked Sendable {
  private let lock = NSRecursiveLock()
  private var storage: UnsafeMutableRawPointer?
  private var storageCount: Int
  private var erased = false
  private let eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?

  public convenience init(copying bytes: UnsafeRawBufferPointer) throws {
    let allocation = try Self.copyIntoOwnedStorage(bytes)
    self.init(storage: allocation, count: bytes.count, eraseObserver: nil)
  }

  public convenience init(copying bytes: [UInt8]) throws {
    let allocation = try bytes.withUnsafeBytes(Self.copyIntoOwnedStorage)
    self.init(storage: allocation, count: bytes.count, eraseObserver: nil)
  }

  convenience init(
    copying bytes: [UInt8],
    eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  ) throws {
    let allocation = try bytes.withUnsafeBytes(Self.copyIntoOwnedStorage)
    self.init(storage: allocation, count: bytes.count, eraseObserver: eraseObserver)
  }

  convenience init(
    copying bytes: UnsafeRawBufferPointer,
    eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  ) throws {
    let allocation = try Self.copyIntoOwnedStorage(bytes)
    self.init(storage: allocation, count: bytes.count, eraseObserver: eraseObserver)
  }

  static func allocate(
    count: Int,
    initialize: (UnsafeMutableRawBufferPointer) throws -> Void
  ) throws -> SecureBytes {
    guard count >= 0, let allocation = malloc(max(count, 1)) else {
      throw SecureBytesError.allocationFailed
    }
    if count > 0 {
      _ = memset(allocation, 0, count)
    }
    do {
      try initialize(UnsafeMutableRawBufferPointer(start: allocation, count: count))
      return SecureBytes(storage: allocation, count: count, eraseObserver: nil)
    } catch {
      explicitBzero(allocation, count)
      free(allocation)
      throw error
    }
  }

  private init(
    storage: UnsafeMutableRawPointer,
    count: Int,
    eraseObserver: (@Sendable (UnsafeRawBufferPointer) -> Void)?
  ) {
    self.storage = storage
    storageCount = count
    self.eraseObserver = eraseObserver
  }

  public var count: Int {
    locked { erased ? 0 : storageCount }
  }

  public func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try locked {
      guard !erased, let storage else { throw SecureBytesError.erased }
      return try body(UnsafeRawBufferPointer(start: storage, count: storageCount))
    }
  }

  public func erase() {
    locked { eraseLocked() }
  }

  deinit {
    lock.lock()
    eraseLocked()
    let allocation = storage
    storage = nil
    lock.unlock()
    free(allocation)
  }

  private func eraseLocked() {
    guard !erased, let storage else { return }
    let originalCount = storageCount
    explicitBzero(storage, originalCount)
    eraseObserver?(UnsafeRawBufferPointer(start: storage, count: originalCount))
    erased = true
    storageCount = 0
  }

  private func locked<Result>(_ body: () throws -> Result) rethrows -> Result {
    lock.lock()
    defer { lock.unlock() }
    return try body()
  }

  private static func copyIntoOwnedStorage(
    _ bytes: UnsafeRawBufferPointer
  ) throws -> UnsafeMutableRawPointer {
    guard let allocation = malloc(max(bytes.count, 1)) else {
      throw SecureBytesError.allocationFailed
    }
    if !bytes.isEmpty {
      _ = memcpy(allocation, bytes.baseAddress!, bytes.count)
    }
    return allocation
  }
}

/// macOS exposes `memset_s`, whose writes cannot be elided, but not the BSD
/// `explicit_bzero` symbol. Keep the semantic boundary named explicitly and
/// implement it with the platform's guaranteed zeroing primitive.
@inline(never)
private func explicitBzero(_ pointer: UnsafeMutableRawPointer, _ count: Int) {
  guard count > 0 else { return }
  _ = memset_s(pointer, count, 0, count)
}
