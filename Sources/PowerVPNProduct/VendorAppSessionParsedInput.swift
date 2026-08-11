import Darwin
import Foundation

/// Owns the bounded append bytes; neither the buffer nor parsed scalar ranges are Codable.
final class VendorAppSessionParsedInput: @unchecked Sendable {
  private let buffer: VendorAppSessionAppendBuffer
  private let dictionaryRange: Range<Int>
  private let root: VendorAppSessionLogNode
  private let sourceSeal: VendorAppSessionSourceSeal

  init(
    buffer: VendorAppSessionAppendBuffer,
    dictionaryRange: Range<Int>,
    root: VendorAppSessionLogNode,
    sourceSeal: VendorAppSessionSourceSeal
  ) {
    self.buffer = buffer
    self.dictionaryRange = dictionaryRange
    self.root = root
    self.sourceSeal = sourceSeal
  }

  func makeMaterial() throws -> VendorAppSessionSnapshotMaterial {
    defer { erase() }
    return try buffer.withUnsafeBytes { bytes in
      guard dictionaryRange.lowerBound >= 0,
        dictionaryRange.upperBound <= bytes.count
      else { throw VendorAppSessionSnapshotError.malformed }
      let dictionaryBytes = UnsafeRawBufferPointer(
        rebasing: bytes[dictionaryRange.lowerBound..<dictionaryRange.upperBound])
      return try VendorAppSessionSnapshotMaterial(
        root: root,
        bytes: dictionaryBytes,
        sourceSeal: sourceSeal
      )
    }
  }

  func erase() {
    buffer.erase()
  }

  var isErased: Bool { buffer.isErased }

  deinit {
    erase()
  }
}

final class VendorAppSessionAppendBuffer: @unchecked Sendable {
  private let lock = NSRecursiveLock()
  private var storage: UnsafeMutableRawPointer?
  private var storageCount: Int
  private var erased = false

  init(count: Int) throws {
    guard (1...VendorAppSessionSnapshotSource.maximumAppendBytes).contains(count),
      let allocation = malloc(count)
    else { throw VendorAppSessionSnapshotError.unavailable }
    _ = memset(allocation, 0, count)
    storage = allocation
    storageCount = count
  }

  var count: Int {
    locked { erased ? 0 : storageCount }
  }

  var isErased: Bool {
    locked { erased }
  }

  func withUnsafeMutableBytes<Result>(
    _ body: (UnsafeMutableRawBufferPointer) throws -> Result
  ) throws -> Result {
    try locked {
      guard !erased, let storage else { throw VendorAppSessionSnapshotError.unavailable }
      return try body(UnsafeMutableRawBufferPointer(start: storage, count: storageCount))
    }
  }

  func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) throws -> Result {
    try locked {
      guard !erased, let storage else { throw VendorAppSessionSnapshotError.unavailable }
      return try body(UnsafeRawBufferPointer(start: storage, count: storageCount))
    }
  }

  func erase() {
    locked {
      guard !erased, let storage else { return }
      _ = memset_s(storage, storageCount, 0, storageCount)
      erased = true
      storageCount = 0
    }
  }

  deinit {
    lock.lock()
    if !erased, let storage {
      _ = memset_s(storage, storageCount, 0, storageCount)
    }
    let allocation = storage
    storage = nil
    lock.unlock()
    free(allocation)
  }

  private func locked<Result>(_ body: () throws -> Result) rethrows -> Result {
    lock.lock()
    defer { lock.unlock() }
    return try body()
  }
}
