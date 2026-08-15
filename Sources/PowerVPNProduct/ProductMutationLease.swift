import Darwin
import Foundation

@_silgen_name("flock")
private func productSystemFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

package enum ProductMutationLeaseError: Error, Equatable, Sendable {
  case stateDirectoryRejected
  case lockFileRejected
  case alreadyHeld
}

package protocol ProductMutationLeaseHolding: Sendable {}

/// Cross-process ownership for the single vendor helper mutation surface.
/// The lock file is intentionally retained after release so contenders always
/// flock the same inode.
package final class ProductMutationLease: ProductMutationLeaseHolding, @unchecked Sendable {
  private let descriptor: Int32

  private init(descriptor: Int32) {
    self.descriptor = descriptor
  }

  deinit {
    _ = productSystemFlock(descriptor, LOCK_UN)
    _ = Darwin.close(descriptor)
  }

  package static func acquireCurrentMachine() throws -> ProductMutationLease {
    let home = FileManager.default.homeDirectoryForCurrentUser
    return try acquire(
      stateDirectory:
        home
        .appendingPathComponent(".local", isDirectory: true)
        .appendingPathComponent("state", isDirectory: true)
        .appendingPathComponent("powervpn", isDirectory: true)
    )
  }

  package static func acquire(
    stateDirectory: URL
  ) throws -> ProductMutationLease {
    do {
      try FileManager.default.createDirectory(
        at: stateDirectory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } catch {
      throw ProductMutationLeaseError.stateDirectoryRejected
    }

    guard ownedDirectory(stateDirectory.path),
      chmod(stateDirectory.path, 0o700) == 0,
      secureDirectory(stateDirectory.path)
    else {
      throw ProductMutationLeaseError.stateDirectoryRejected
    }

    let lockPath = stateDirectory.appendingPathComponent("mutation.lock").path
    let descriptor = Darwin.open(
      lockPath,
      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
      mode_t(0o600)
    )
    guard descriptor >= 0 else {
      throw ProductMutationLeaseError.lockFileRejected
    }

    var shouldClose = true
    defer {
      if shouldClose { _ = Darwin.close(descriptor) }
    }

    var status = stat()
    guard fstat(descriptor, &status) == 0,
      status.st_uid == getuid(),
      (status.st_mode & S_IFMT) == S_IFREG,
      fchmod(descriptor, 0o600) == 0
    else {
      throw ProductMutationLeaseError.lockFileRejected
    }

    guard productSystemFlock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      if errno == EWOULDBLOCK {
        throw ProductMutationLeaseError.alreadyHeld
      }
      throw ProductMutationLeaseError.lockFileRejected
    }

    shouldClose = false
    return ProductMutationLease(descriptor: descriptor)
  }

  private static func ownedDirectory(_ path: String) -> Bool {
    var status = stat()
    guard lstat(path, &status) == 0 else { return false }
    return status.st_uid == getuid() && (status.st_mode & S_IFMT) == S_IFDIR
  }

  private static func secureDirectory(_ path: String) -> Bool {
    var status = stat()
    guard lstat(path, &status) == 0 else { return false }
    return status.st_uid == getuid()
      && (status.st_mode & S_IFMT) == S_IFDIR
      && (status.st_mode & 0o777) == 0o700
  }
}
