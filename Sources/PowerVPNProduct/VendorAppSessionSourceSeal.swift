import Darwin

struct VendorAppSessionSourceSeal: Sendable {
  let device: UInt64
  let inode: UInt64
  let size: Int64
  let ownerUID: UInt32
  let mode: UInt32
  let modificationSeconds: Int64
  let modificationNanoseconds: Int
  let changeSeconds: Int64
  let changeNanoseconds: Int

  init(_ metadata: stat) {
    device = UInt64(metadata.st_dev)
    inode = UInt64(metadata.st_ino)
    size = Int64(metadata.st_size)
    ownerUID = UInt32(metadata.st_uid)
    mode = UInt32(metadata.st_mode)
    modificationSeconds = Int64(metadata.st_mtimespec.tv_sec)
    modificationNanoseconds = metadata.st_mtimespec.tv_nsec
    changeSeconds = Int64(metadata.st_ctimespec.tv_sec)
    changeNanoseconds = metadata.st_ctimespec.tv_nsec
  }

  func isCurrent(path: String = VendorAppOnboardingCursor.installedSourcePath) -> Bool {
    let descriptor = path.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) }
    guard descriptor >= 0 else { return false }
    defer { close(descriptor) }
    var descriptorState = stat()
    var pathState = stat()
    return fstat(descriptor, &descriptorState) == 0
      && path.withCString({ lstat($0, &pathState) }) == 0
      && matches(descriptorState) && matches(pathState)
      && descriptorState.st_nlink == 1
      && VendorAppInstalledLogSecurity.hasNoExtendedACL(descriptor)
      && VendorAppInstalledLogSecurity.endsAtLineBoundary(
        descriptor, size: descriptorState.st_size)
  }

  private func matches(_ metadata: stat) -> Bool {
    UInt64(metadata.st_dev) == device && UInt64(metadata.st_ino) == inode
      && Int64(metadata.st_size) == size && UInt32(metadata.st_uid) == ownerUID
      && UInt32(metadata.st_mode) == mode
      && Int64(metadata.st_mtimespec.tv_sec) == modificationSeconds
      && metadata.st_mtimespec.tv_nsec == modificationNanoseconds
      && Int64(metadata.st_ctimespec.tv_sec) == changeSeconds
      && metadata.st_ctimespec.tv_nsec == changeNanoseconds
  }
}
