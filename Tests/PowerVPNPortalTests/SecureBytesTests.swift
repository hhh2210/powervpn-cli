import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct SecureBytesTests {
  @Test func copiesRawBytesWithoutExposingOwnedStorage() throws {
    let source: [UInt8] = [0x41, 0x42, 0x43, 0x00]
    let secure = try source.withUnsafeBytes { try SecureBytes(copying: $0) }

    source.withUnsafeBytes { sourceBuffer in
      try? secure.withUnsafeBytes { ownedBuffer in
        #expect(ownedBuffer.elementsEqual(sourceBuffer))
        #expect(ownedBuffer.baseAddress != sourceBuffer.baseAddress)
      }
    }
    #expect(secure.count == source.count)
  }

  @Test func eraseZerosOwnedBytesAndIsIdempotent() throws {
    let observation = EraseObservation()
    let syntheticSecret = Array("secure-byte-sentinel".utf8)
    let secure = try SecureBytes(copying: syntheticSecret) {
      observation.record($0)
    }

    secure.erase()
    secure.erase()

    #expect(secure.count == 0)
    #expect(observation.snapshots == [[UInt8](repeating: 0, count: syntheticSecret.count)])
    #expect(throws: SecureBytesError.self) {
      _ = try secure.withUnsafeBytes(\.count)
    }
  }

  @Test func deinitZerosBeforeOwnedStorageIsReleased() throws {
    let observation = EraseObservation()
    do {
      let secure = try SecureBytes(copying: [0xde, 0xad, 0xbe, 0xef]) {
        observation.record($0)
      }
      #expect(secure.count == 4)
    }
    #expect(observation.snapshots == [[0, 0, 0, 0]])
  }

  @Test func sameThreadReentryIsBoundedAndEraseIsImmediate() throws {
    let secret = Array("secure-bytes-reentry-sentinel".utf8)
    let secure = try SecureBytes(copying: secret)
    let result = ReentrancyResultBox()
    let completed = DispatchSemaphore(value: 0)

    DispatchQueue.global().async {
      var checks: [Bool] = []
      do {
        try secure.withUnsafeBytes { outer in
          checks.append(secure.count == secret.count)
          checks.append(try secure.withUnsafeBytes { $0.elementsEqual(secret) })
          secure.erase()
          checks.append(outer.allSatisfy { $0 == 0 })
          checks.append(secure.count == 0)
          do {
            _ = try secure.withUnsafeBytes(\.count)
            checks.append(false)
          } catch SecureBytesError.erased {
            checks.append(true)
          } catch {
            checks.append(false)
          }
        }
        result.store(checks)
      } catch {
        result.store([])
      }
      completed.signal()
    }

    #expect(completed.wait(timeout: .now() + 1) == .success)
    #expect(result.load() == [true, true, true, true, true])
  }
}

private final class ReentrancyResultBox: @unchecked Sendable {
  private let lock = NSLock()
  private var result: [Bool] = []

  func store(_ value: [Bool]) {
    lock.withLock { result = value }
  }

  func load() -> [Bool] {
    lock.withLock { result }
  }
}

private final class EraseObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [[UInt8]] = []

  var snapshots: [[UInt8]] {
    lock.withLock { storage }
  }

  func record(_ bytes: UnsafeRawBufferPointer) {
    lock.withLock { storage.append(Array(bytes)) }
  }
}
