import CryptoKit
import Darwin
import Foundation

struct InstalledArtifactRead: Sendable {
  let sha256: String
  let capturedData: Data?
}

enum BoundedInstalledArtifactReader {
  static func read(
    _ spec: InstalledArtifactSpec,
    owner: uid_t,
    captureData: Bool
  ) throws -> InstalledArtifactRead {
    var pathMetadata = stat()
    guard lstat(spec.path, &pathMetadata) == 0 else {
      throw InstalledConfigDiscoveryError.missingArtifact
    }
    guard pathMetadata.st_mode & S_IFMT != S_IFLNK else {
      throw InstalledConfigDiscoveryError.symbolicLink
    }
    guard pathMetadata.st_mode & S_IFMT == S_IFREG else {
      throw InstalledConfigDiscoveryError.notRegularFile
    }

    let descriptor = open(spec.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw InstalledConfigDiscoveryError.readFailed }
    defer { close(descriptor) }

    var openedMetadata = stat()
    guard fstat(descriptor, &openedMetadata) == 0 else {
      throw InstalledConfigDiscoveryError.readFailed
    }
    guard openedMetadata.st_dev == pathMetadata.st_dev,
      openedMetadata.st_ino == pathMetadata.st_ino
    else {
      throw InstalledConfigDiscoveryError.readFailed
    }
    guard openedMetadata.st_mode & S_IFMT == S_IFREG else {
      throw InstalledConfigDiscoveryError.notRegularFile
    }
    guard openedMetadata.st_uid == owner else {
      throw InstalledConfigDiscoveryError.ownerMismatch
    }
    guard openedMetadata.st_mode & 0o7777 == spec.mode else {
      throw InstalledConfigDiscoveryError.modeMismatch
    }
    guard openedMetadata.st_size > 0,
      openedMetadata.st_size <= off_t(spec.maximumByteCount)
    else {
      throw InstalledConfigDiscoveryError.sizeOutOfBounds
    }

    var hasher = SHA256()
    var captured = captureData ? Data() : nil
    var total = 0
    var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
    while true {
      let count = buffer.withUnsafeMutableBytes {
        Darwin.read(descriptor, $0.baseAddress, $0.count)
      }
      guard count >= 0 else { throw InstalledConfigDiscoveryError.readFailed }
      guard count != 0 else { break }
      total += count
      guard total <= spec.maximumByteCount else {
        throw InstalledConfigDiscoveryError.sizeOutOfBounds
      }
      buffer.withUnsafeBytes { bytes in
        let chunk = UnsafeRawBufferPointer(rebasing: bytes[..<count])
        hasher.update(bufferPointer: chunk)
        captured?.append(chunk.bindMemory(to: UInt8.self))
      }
    }
    guard total == Int(openedMetadata.st_size) else {
      throw InstalledConfigDiscoveryError.readFailed
    }

    var finalMetadata = stat()
    guard fstat(descriptor, &finalMetadata) == 0,
      finalMetadata.st_size == openedMetadata.st_size,
      finalMetadata.st_mtimespec.tv_sec == openedMetadata.st_mtimespec.tv_sec,
      finalMetadata.st_mtimespec.tv_nsec == openedMetadata.st_mtimespec.tv_nsec
    else {
      throw InstalledConfigDiscoveryError.readFailed
    }

    let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
    return InstalledArtifactRead(sha256: digest, capturedData: captured)
  }
}
