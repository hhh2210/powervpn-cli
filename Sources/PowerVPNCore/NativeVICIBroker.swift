import Darwin
import Foundation

/// A bounded, frame-aware relay. Every client frame is checked, including frames
/// sent after an allowed request; daemon events can flow in the other direction.
package enum NativeVICIBroker {
  package static func relay(client: Int32, upstream: Int32) {
    for fd in [client, upstream] {
      var timeout = timeval(tv_sec: 20, tv_usec: 0)
      var enabled: Int32 = 1
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
    }
    var descriptors = [
      pollfd(fd: client, events: Int16(POLLIN), revents: 0),
      pollfd(fd: upstream, events: Int16(POLLIN), revents: 0),
    ]
    while true {
      let result = poll(&descriptors, nfds_t(descriptors.count), 30_000)
      if result < 0, errno == EINTR { continue }
      guard result > 0 else { return }
      for index in descriptors.indices {
        let events = descriptors[index].revents
        if events & Int16(POLLIN) != 0 {
          guard var payload = readFrame(descriptors[index].fd) else { return }
          defer { payload.resetBytes(in: 0..<payload.count) }
          guard index != 0 || NativeVICIAllowlist.permits(payload) else { return }
          let destination = index == 0 ? upstream : client
          guard writeFrame(destination, payload) else { return }
        } else if events & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 {
          return
        }
      }
    }
  }

  package static func readFrame(_ fd: Int32) -> Data? {
    guard let header = readExactly(fd, count: 4) else { return nil }
    let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard length > 0, length <= VICIMessageCodec.maximumPayloadSize else { return nil }
    return readExactly(fd, count: Int(length))
  }

  package static func writeFrame(_ fd: Int32, _ payload: Data) -> Bool {
    let length = UInt32(payload.count)
    let header = Data([
      UInt8(length >> 24), UInt8((length >> 16) & 255),
      UInt8((length >> 8) & 255), UInt8(length & 255),
    ])
    return writeAll(fd, header) && writeAll(fd, payload)
  }

  private static func readExactly(_ fd: Int32, count: Int) -> Data? {
    var data = Data(count: count)
    var offset = 0
    let deadline = DispatchTime.now().uptimeNanoseconds + 20_000_000_000
    while offset < count {
      let now = DispatchTime.now().uptimeNanoseconds
      guard now < deadline else { return nil }
      var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
      let waited = poll(&ready, 1, Int32(max(1, (deadline - now) / 1_000_000)))
      if waited < 0, errno == EINTR { continue }
      guard waited > 0, ready.revents & Int16(POLLIN) != 0 else { return nil }
      let received = data.withUnsafeMutableBytes {
        Darwin.read(fd, $0.baseAddress!.advanced(by: offset), count - offset)
      }
      if received < 0, errno == EINTR { continue }
      guard received > 0 else { return nil }
      offset += received
    }
    return data
  }
}
