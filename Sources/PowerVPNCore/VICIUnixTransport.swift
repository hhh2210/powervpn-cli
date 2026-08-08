import Darwin
import Dispatch
import Foundation

public final class VICIUnixTransport: VICIFrameTransport {
  private var descriptor: Int32
  private let timeoutMilliseconds: Int

  public init(socketPath: String, timeoutMilliseconds: Int = 2_000) throws {
    guard (1...60_000).contains(timeoutMilliseconds) else {
      throw VICITransportError.invalidTimeout
    }
    self.timeoutMilliseconds = timeoutMilliseconds
    descriptor = -1

    let pathBytes = Array(socketPath.utf8) + [0]
    var address = sockaddr_un()
    let pathCapacity = MemoryLayout.size(ofValue: address.sun_path)
    guard pathBytes.count > 1, pathBytes.count <= pathCapacity else {
      throw VICITransportError.invalidSocketPath
    }

    let socketDescriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard socketDescriptor >= 0 else {
      throw VICITransportError.socketCreationFailed(errno)
    }

    do {
      try Self.configure(socketDescriptor)
      address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
      address.sun_family = sa_family_t(AF_UNIX)
      withUnsafeMutableBytes(of: &address.sun_path) { destination in
        pathBytes.withUnsafeBytes { source in
          destination.copyBytes(from: source)
        }
      }
      try Self.connect(
        socketDescriptor,
        address: &address,
        timeoutMilliseconds: timeoutMilliseconds
      )
      descriptor = socketDescriptor
    } catch {
      Darwin.close(socketDescriptor)
      throw error
    }
  }

  init(connectedFileDescriptor: Int32, timeoutMilliseconds: Int) throws {
    guard (1...60_000).contains(timeoutMilliseconds) else {
      throw VICITransportError.invalidTimeout
    }
    self.timeoutMilliseconds = timeoutMilliseconds
    descriptor = connectedFileDescriptor
    do {
      try Self.configure(connectedFileDescriptor)
    } catch {
      Darwin.close(connectedFileDescriptor)
      descriptor = -1
      throw error
    }
  }

  deinit {
    close()
  }

  public func send(payload: Data) throws -> Int {
    guard payload.count <= VICIMessageCodec.maximumPayloadSize else {
      throw VICITransportError.frameTooLarge(payload.count)
    }
    guard !payload.isEmpty else { throw VICITransportError.emptyFrame }

    let length = UInt32(payload.count)
    var frame = Data([
      UInt8(length >> 24), UInt8((length >> 16) & 0xff),
      UInt8((length >> 8) & 0xff), UInt8(length & 0xff),
    ])
    frame.append(payload)
    try writeAll(frame, deadline: deadline())
    return frame.count
  }

  public func receive() throws -> VICIReceivedFrame {
    let expiry = deadline()
    let header = try readExactly(4, phase: .readHeader, deadline: expiry)
    let length = header.reduce(0) { ($0 << 8) | Int($1) }
    guard length > 0 else { throw VICITransportError.emptyFrame }
    guard length <= VICIMessageCodec.maximumPayloadSize else {
      throw VICITransportError.frameTooLarge(length)
    }
    let payload = try readExactly(length, phase: .readPayload, deadline: expiry)
    return VICIReceivedFrame(payload: payload, wireByteCount: 4 + payload.count)
  }

  public func close() {
    if descriptor >= 0 {
      Darwin.close(descriptor)
      descriptor = -1
    }
  }

  private func writeAll(_ data: Data, deadline: UInt64) throws {
    var offset = 0
    while offset < data.count {
      try wait(for: Int16(POLLOUT), phase: .writeFrame, deadline: deadline)
      let written = data.withUnsafeBytes { bytes -> Int in
        guard let base = bytes.baseAddress else { return 0 }
        return Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
      }
      if written > 0 {
        offset += written
      } else if written == 0 {
        throw VICITransportError.unexpectedEOF(
          .writeFrame, expected: data.count, received: offset
        )
      } else if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
        throw VICITransportError.writeFailed(errno)
      }
    }
  }

  private func readExactly(
    _ count: Int,
    phase: VICITransportPhase,
    deadline: UInt64
  ) throws -> Data {
    var data = Data()
    data.reserveCapacity(count)
    while data.count < count {
      try wait(for: Int16(POLLIN), phase: phase, deadline: deadline)
      var buffer = [UInt8](repeating: 0, count: min(16_384, count - data.count))
      let readCount = buffer.withUnsafeMutableBytes { bytes -> Int in
        Darwin.read(descriptor, bytes.baseAddress, bytes.count)
      }
      if readCount > 0 {
        data.append(contentsOf: buffer.prefix(readCount))
      } else if readCount == 0 {
        throw VICITransportError.unexpectedEOF(
          phase, expected: count, received: data.count
        )
      } else if errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK {
        throw VICITransportError.readFailed(phase, errno)
      }
    }
    return data
  }

  private func wait(
    for events: Int16,
    phase: VICITransportPhase,
    deadline: UInt64
  ) throws {
    while true {
      let now = DispatchTime.now().uptimeNanoseconds
      guard now < deadline else { throw VICITransportError.timeout(phase) }
      let remaining = deadline - now
      let milliseconds = max(
        1, min(Int(Int32.max), Int((remaining + 999_999) / 1_000_000))
      )
      var pollDescriptor = pollfd(fd: descriptor, events: events, revents: 0)
      let result = Darwin.poll(&pollDescriptor, 1, Int32(milliseconds))
      if result > 0 {
        if pollDescriptor.revents & events != 0 { return }
        if pollDescriptor.revents & Int16(POLLHUP) != 0 {
          if events == Int16(POLLIN) { return }
          throw VICITransportError.unexpectedEOF(phase, expected: 1, received: 0)
        }
        if pollDescriptor.revents & (Int16(POLLERR) | Int16(POLLNVAL)) != 0 {
          throw VICITransportError.readFailed(phase, EIO)
        }
      } else if result == 0 {
        throw VICITransportError.timeout(phase)
      } else if errno != EINTR {
        if phase == .writeFrame {
          throw VICITransportError.writeFailed(errno)
        }
        throw VICITransportError.readFailed(phase, errno)
      }
    }
  }

  private func deadline() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds + UInt64(timeoutMilliseconds) * 1_000_000
  }

  private static func configure(_ descriptor: Int32) throws {
    let statusFlags = fcntl(descriptor, F_GETFL)
    guard statusFlags >= 0, fcntl(descriptor, F_SETFL, statusFlags | O_NONBLOCK) == 0 else {
      throw VICITransportError.socketConfigurationFailed(errno)
    }
    guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
      throw VICITransportError.socketConfigurationFailed(errno)
    }
    var enabled: Int32 = 1
    guard
      setsockopt(
        descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
        socklen_t(MemoryLayout<Int32>.size)
      ) == 0
    else {
      throw VICITransportError.socketConfigurationFailed(errno)
    }
  }

  private static func connect(
    _ descriptor: Int32,
    address: inout sockaddr_un,
    timeoutMilliseconds: Int
  ) throws {
    let result = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        Darwin.connect(
          descriptor, socketAddress, socklen_t(MemoryLayout<sockaddr_un>.size)
        )
      }
    }
    if result == 0 { return }
    guard errno == EINPROGRESS || errno == EAGAIN else {
      throw VICITransportError.connectFailed(errno)
    }

    let deadline =
      DispatchTime.now().uptimeNanoseconds
      + UInt64(timeoutMilliseconds) * 1_000_000
    while true {
      let now = DispatchTime.now().uptimeNanoseconds
      guard now < deadline else { throw VICITransportError.timeout(.connect) }
      let remaining = deadline - now
      let milliseconds = max(
        1, min(Int(Int32.max), Int((remaining + 999_999) / 1_000_000))
      )
      var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
      let pollResult = Darwin.poll(&pollDescriptor, 1, Int32(milliseconds))
      if pollResult > 0 {
        var socketError: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0 else {
          throw VICITransportError.connectFailed(errno)
        }
        guard socketError == 0 else { throw VICITransportError.connectFailed(socketError) }
        return
      }
      if pollResult == 0 { throw VICITransportError.timeout(.connect) }
      if errno != EINTR { throw VICITransportError.connectFailed(errno) }
    }
  }
}
