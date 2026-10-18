import Darwin
import Foundation
import PowerVPNCore

func serveVICI(owner: uid_t) {
  let path = NativeHelperPaths.vici
  unlink(path)
  let listener = socket(AF_UNIX, SOCK_STREAM, 0)
  guard listener >= 0, var address = unixAddress(path) else { fail("vici proxy socket") }
  let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
  }
  guard bound == 0, chown(path, owner, 0) == 0, chmod(path, 0o600) == 0,
    listen(listener, 16) == 0
  else { fail("vici proxy bind") }
  let slots = DispatchSemaphore(value: 16)
  while true {
    let client = accept(listener, nil, nil)
    if client < 0 { continue }
    var uid: uid_t = 0
    var gid: gid_t = 0
    guard getpeereid(client, &uid, &gid) == 0, uid == owner || uid == 0,
      slots.wait(timeout: .now()) == .success
    else {
      close(client)
      continue
    }
    DispatchQueue.global().async {
      defer {
        close(client)
        slots.signal()
      }
      let upstream = socket(AF_UNIX, SOCK_STREAM, 0)
      guard upstream >= 0 else { return }
      defer { close(upstream) }
      guard var upstreamAddress = unixAddress(NativeHelperPaths.charonVICI) else { return }
      let connected = withUnsafePointer(to: &upstreamAddress) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          connect(upstream, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
      }
      guard connected == 0 else { return }
      NativeVICIBroker.relay(client: client, upstream: upstream)
    }
  }
}
