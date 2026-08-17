import Darwin
import Dispatch
import Foundation
import Testing

@testable import PowerVPNCore

@Suite struct VICIUnixTransportTests {
  @Test func exchangesExactlyFramedVersionAcrossPartialReads() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 500
    )
    let responseMessage = VICIMessage(elements: [
      .keyValue("daemon", "charon"),
      .keyValue("version", "6.0.7"),
    ])
    let responsePayload =
      Data([VICIPacketOperation.commandResponse.rawValue])
      + (try VICIMessageCodec.encode(responseMessage))
    let responseFrame = frame(responsePayload)
    let server = sockets.server

    DispatchQueue.global().async {
      let request = readExactly(server, count: 13)
      let expected = Data([
        0x00, 0x00, 0x00, 0x09,
        0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
      ])
      if request == expected {
        writeAll(server, responseFrame.prefix(2))
        usleep(10_000)
        writeAll(server, responseFrame.dropFirst(2).prefix(3))
        usleep(10_000)
        writeAll(server, responseFrame.dropFirst(5))
      } else {
        writeAll(server, frame(Data([VICIPacketOperation.commandUnknown.rawValue])))
      }
      Darwin.close(server)
    }

    let result = try VICISession(transport: transport).version()
    #expect(result.message == responseMessage)
    #expect(result.trace.requestPayloadBytes == 9)
    #expect(result.trace.requestWireBytes == 13)
    #expect(result.trace.responsePayloadBytes == responsePayload.count)
    #expect(result.trace.responseWireBytes == responseFrame.count)
    #expect(result.trace.responseOperation == .commandResponse)
  }

  @Test func timesOutAtTheExactReadPhase() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 30
    )
    defer { Darwin.close(sockets.server) }

    try expectTransportError(.timeout(.readHeader)) {
      try transport.receive()
    }
  }

  @Test func reportsPartialHeaderEOFWithoutParsing() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 100
    )
    writeAll(sockets.server, Data([0x00, 0x00]))
    Darwin.close(sockets.server)

    try expectTransportError(.unexpectedEOF(.readHeader, expected: 4, received: 2)) {
      try transport.receive()
    }
  }

  @Test func rejectsOversizedFrameBeforeReadingPayload() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 100
    )
    defer { Darwin.close(sockets.server) }
    let oversized = VICIMessageCodec.maximumPayloadSize + 1
    writeAll(
      sockets.server,
      Data([
        UInt8(oversized >> 24), UInt8((oversized >> 16) & 0xff),
        UInt8((oversized >> 8) & 0xff), UInt8(oversized & 0xff),
      ])
    )

    try expectTransportError(.frameTooLarge(oversized)) {
      try transport.receive()
    }
  }

  @Test func reportsPartialPayloadEOFWithoutReturningData() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 100
    )
    writeAll(sockets.server, Data([0x00, 0x00, 0x00, 0x04, 0x01, 0x02]))
    Darwin.close(sockets.server)

    try expectTransportError(.unexpectedEOF(.readPayload, expected: 4, received: 2)) {
      try transport.receive()
    }
  }

  @Test func totalDeadlineDoesNotResetAfterPartialHeader() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 50
    )
    let server = sockets.server
    let group = DispatchGroup()
    let partialHeaderWritten = DispatchSemaphore(value: 0)
    group.enter()
    DispatchQueue.global().async {
      writeAll(server, Data([0x00, 0x00]))
      partialHeaderWritten.signal()
      usleep(30_000)
      writeAll(server, Data([0x00, 0x04, 0x01]))
      usleep(70_000)
      Darwin.close(server)
      group.leave()
    }

    #expect(partialHeaderWritten.wait(timeout: .now() + .seconds(1)) == .success)
    let started = ContinuousClock.now
    try expectTransportError(.timeout(.readPayload)) {
      try transport.receive()
    }
    let elapsed = started.duration(to: .now).components
    let milliseconds =
      elapsed.seconds * 1_000
      + elapsed.attoseconds / 1_000_000_000_000_000
    #expect(milliseconds >= 40)
    #expect(milliseconds < 80)
    group.wait()
  }

  @Test func writeUsesTheSameBoundedDeadlineAcrossPartialProgress() throws {
    let sockets = try makeSocketPair()
    var sendBuffer: Int32 = 1_024
    #expect(
      setsockopt(
        sockets.client, SOL_SOCKET, SO_SNDBUF, &sendBuffer,
        socklen_t(MemoryLayout<Int32>.size)
      ) == 0
    )
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 30
    )
    defer { Darwin.close(sockets.server) }
    let payload = Data(repeating: 0x01, count: VICIMessageCodec.maximumPayloadSize)

    try expectTransportError(.timeout(.writeFrame)) {
      try transport.send(payload: payload)
    }
  }

  @Test func rejectsEmptyAndOverlongUnixPaths() throws {
    try expectTransportError(.invalidSocketPath) {
      try VICIUnixTransport(socketPath: "", timeoutMilliseconds: 100)
    }
    try expectTransportError(.invalidSocketPath) {
      try VICIUnixTransport(
        socketPath: "/" + String(repeating: "a", count: 200),
        timeoutMilliseconds: 100
      )
    }
  }

  @Test func closeIsIdempotent() throws {
    let sockets = try makeSocketPair()
    let transport = try VICIUnixTransport(
      connectedFileDescriptor: sockets.client,
      timeoutMilliseconds: 100
    )
    defer { Darwin.close(sockets.server) }
    transport.close()
    transport.close()
  }
}

private struct SocketPair {
  let client: Int32
  let server: Int32
}

private func makeSocketPair() throws -> SocketPair {
  var descriptors: [Int32] = [-1, -1]
  guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
    throw VICITransportError.socketCreationFailed(errno)
  }
  return SocketPair(client: descriptors[0], server: descriptors[1])
}

private func frame(_ payload: Data) -> Data {
  let length = UInt32(payload.count)
  return Data([
    UInt8(length >> 24), UInt8((length >> 16) & 0xff),
    UInt8((length >> 8) & 0xff), UInt8(length & 0xff),
  ]) + payload
}

private func readExactly(_ descriptor: Int32, count: Int) -> Data {
  var result = Data()
  while result.count < count {
    var buffer = [UInt8](repeating: 0, count: count - result.count)
    let readCount = buffer.withUnsafeMutableBytes {
      Darwin.read(descriptor, $0.baseAddress, $0.count)
    }
    guard readCount > 0 else { break }
    result.append(contentsOf: buffer.prefix(readCount))
  }
  return result
}

private func writeAll<C: Collection>(_ descriptor: Int32, _ bytes: C)
where C.Element == UInt8 {
  let data = Data(bytes)
  var offset = 0
  while offset < data.count {
    let written = data.withUnsafeBytes { buffer -> Int in
      guard let base = buffer.baseAddress else { return 0 }
      return Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
    }
    guard written > 0 else { return }
    offset += written
  }
}

private func expectTransportError<T>(
  _ expected: VICITransportError,
  _ operation: () throws -> T
) throws {
  do {
    _ = try operation()
    Issue.record("expected VICI transport error")
  } catch let error as VICITransportError {
    #expect(error == expected)
  }
}
