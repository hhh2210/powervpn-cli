import Darwin
import Foundation

package enum NativeHostPolicy {
  package static func parse(_ text: String) -> Set<String>? {
    let hosts = text.split(whereSeparator: \.isNewline).map(String.init)
    guard !hosts.isEmpty, hosts.count <= 256,
      hosts.allSatisfy({ parseStrictIPv4($0).map(nativeRoutableHost) == true })
    else { return nil }
    return Set(hosts)
  }
}

/// The daemon loads only files owned by root without a second writable alias.
/// Relative library symlinks are permitted only when they resolve inside this
/// validated tree. The installer strips ACLs before this check and activation.
package enum NativeInstallValidation {
  package static func hasNoACL(_ path: String) -> Bool {
    var info = stat()
    guard lstat(path, &info) == 0 else { return false }
    errno = 0
    // Darwin reports ENOENT when an existing node has no extended ACL.
    guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return errno == ENOENT }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    errno = 0
    let result = acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
    return result == -1 && errno == EINVAL
  }

  package static func validateTree(_ path: String, owner: uid_t = 0) -> Bool {
    let root = URL(fileURLWithPath: path).standardizedFileURL.path
    guard root == URL(fileURLWithPath: root).resolvingSymlinksInPath().path,
      validateNode(root, root: root, owner: owner),
      let children = FileManager.default.enumerator(atPath: root)
    else { return false }
    for case let child as String in children {
      guard validateNode(root + "/" + child, root: root, owner: owner) else { return false }
    }
    return true
  }

  private static func validateNode(_ path: String, root: String, owner: uid_t) -> Bool {
    var info = stat()
    guard lstat(path, &info) == 0, info.st_uid == owner, info.st_mode & 0o6000 == 0,
      hasNoACL(path)
    else { return false }
    switch info.st_mode & S_IFMT {
    case S_IFLNK:
      guard let target = try? FileManager.default.destinationOfSymbolicLink(atPath: path),
        !target.hasPrefix("/")
      else { return false }
      let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
      guard resolved.hasPrefix(root + "/"), resolved != path,
        stat(resolved, &info) == 0, info.st_uid == owner,
        info.st_mode & 0o022 == 0
      else { return false }
      return true
    case S_IFREG: return info.st_mode & 0o022 == 0 && info.st_nlink == 1
    case S_IFDIR: return info.st_mode & 0o022 == 0
    default: return false
    }
  }
}
