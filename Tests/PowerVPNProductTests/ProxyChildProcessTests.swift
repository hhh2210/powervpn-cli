import Darwin
import Foundation
import Testing

@testable import PowerVPNCLI

@Suite struct ProxyChildProcessTests {
  @Test func cancellationAfterSpawnTerminatesAndReapsChild() async {
    let runner = FoundationProxyChildRunner()
    let task = Task {
      await runner.run(
        ProxyChildSpecification(
          executable: "/bin/sleep",
          arguments: ["10"],
          standardInput: .null,
          standardOutput: .null
        ),
        readiness: .none,
        onReady: {}
      )
    }
    try? await Task.sleep(for: .milliseconds(50))
    task.cancel()
    let result = await task.value
    #expect(result.outcome == .cancelled)
  }

  @Test func loopbackReadinessFiresOnceAndCancellationReapsListener() async throws {
    let port = try unusedLoopbackPort()
    let readiness = M2CommandTrace()
    let runner = FoundationProxyChildRunner()
    let task = Task {
      await runner.run(
        ProxyChildSpecification(
          executable: "/usr/bin/nc",
          arguments: ["-l", "-k", "127.0.0.1", String(port)],
          standardInput: .null,
          standardOutput: .null
        ),
        readiness: .loopback(port: port, timeoutMilliseconds: 2_000),
        onReady: { readiness.record("ready") }
      )
    }

    let deadline = ContinuousClock.now + .seconds(2)
    while readiness.events.isEmpty, ContinuousClock.now < deadline {
      try? await Task.sleep(for: .milliseconds(10))
    }
    #expect(readiness.events == ["ready"])
    task.cancel()
    let result = await task.value
    #expect(result.outcome == .cancelled)
    #expect(result.becameReady)
  }
}

private func unusedLoopbackPort() throws -> UInt16 {
  let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
  guard descriptor >= 0 else { throw ProxySocketTestError.socket }
  defer { Darwin.close(descriptor) }
  var address = sockaddr_in()
  address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
  address.sin_family = sa_family_t(AF_INET)
  address.sin_port = 0
  address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
  let bound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
  }
  guard bound == 0 else { throw ProxySocketTestError.bind }
  var length = socklen_t(MemoryLayout<sockaddr_in>.size)
  let named = withUnsafeMutablePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.getsockname(descriptor, $0, &length)
    }
  }
  guard named == 0 else { throw ProxySocketTestError.name }
  return UInt16(bigEndian: address.sin_port)
}

private enum ProxySocketTestError: Error {
  case socket
  case bind
  case name
}
