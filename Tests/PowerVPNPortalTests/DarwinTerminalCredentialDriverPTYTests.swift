import Darwin
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite(.serialized) struct DarwinTerminalCredentialDriverPTYTests {
  @Test func taskCancellationRestoresTerminalWithinTwoHundredMilliseconds() async throws {
    let terminal = try PseudoTerminal()
    defer { terminal.close() }
    let originalState = try terminal.state()
    let reader = DarwinSecureTerminalCredentialReader(
      driver: DarwinTerminalCredentialDriver(terminalPath: terminal.slavePath)
    )
    let readTask = Task.detached { () -> SecureTerminalCredentialError? in
      do {
        let credentials = try reader.readCredentials()
        credentials.erase()
        return nil
      } catch let error as SecureTerminalCredentialError {
        return error
      } catch {
        return .unavailable
      }
    }
    defer { readTask.cancel() }

    let output = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.username.rawValue,
      timeoutMilliseconds: 1_000
    )
    #expect(output.contains(SecureTerminalCredentialPrompt.username.rawValue))
    let hiddenState = try terminal.state()
    #expect(hiddenState.c_lflag & tcflag_t(ECHO | ECHONL) == 0)

    let clock = ContinuousClock()
    let cancellationStart = clock.now
    readTask.cancel()
    let outcome = await readTask.value
    let cancellationDuration = cancellationStart.duration(to: clock.now)

    #expect(outcome == .cancelled)
    #expect(cancellationDuration < .milliseconds(200))
    let restoredState = try terminal.state()
    #expect(restoredState.c_iflag == originalState.c_iflag)
    #expect(restoredState.c_oflag == originalState.c_oflag)
    #expect(restoredState.c_cflag == originalState.c_cflag)
    #expect(restoredState.c_lflag == originalState.c_lflag)
  }
  @Test func successfulCredentialReadRestoresTerminalAndKeepsPromptsHidden() async throws {
    let terminal = try PseudoTerminal()
    defer { terminal.close() }
    let originalState = try terminal.state()
    let reader = DarwinSecureTerminalCredentialReader(
      driver: DarwinTerminalCredentialDriver(terminalPath: terminal.slavePath)
    )
    let readTask = Task.detached { try reader.readCredentials() }
    defer { readTask.cancel() }

    _ = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.username.rawValue,
      timeoutMilliseconds: 1_000
    )
    #expect(try terminal.state().c_lflag & tcflag_t(ECHO | ECHONL) == 0)
    try terminal.writeLine("pty-user")
    _ = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.password.rawValue,
      timeoutMilliseconds: 1_000
    )
    #expect(try terminal.state().c_lflag & tcflag_t(ECHO | ECHONL) == 0)
    try terminal.writeLine("pty-password")

    let credentials = try await readTask.value
    defer { credentials.erase() }
    #expect(
      try credentials.withUsernameBytes { String(decoding: $0, as: UTF8.self) } == "pty-user")
    #expect(
      try credentials.withPasswordBytes { String(decoding: $0, as: UTF8.self) }
        == "pty-password")
    try expectSameTerminalFlags(terminal.state(), originalState)
  }

  @Test func emptyCredentialErrorRestoresTerminal() async throws {
    let terminal = try PseudoTerminal()
    defer { terminal.close() }
    let originalState = try terminal.state()
    let reader = DarwinSecureTerminalCredentialReader(
      driver: DarwinTerminalCredentialDriver(terminalPath: terminal.slavePath)
    )
    let readTask = Task.detached { () -> SecureTerminalCredentialError? in
      do {
        let credentials = try reader.readCredentials()
        credentials.erase()
        return nil
      } catch let error as SecureTerminalCredentialError {
        return error
      } catch {
        return .unavailable
      }
    }
    defer { readTask.cancel() }

    _ = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.username.rawValue,
      timeoutMilliseconds: 1_000
    )
    try terminal.writeLine("")

    #expect(await readTask.value == .empty(.username))
    try expectSameTerminalFlags(terminal.state(), originalState)
  }

  private func expectSameTerminalFlags(_ actual: termios, _ expected: termios) throws {
    #expect(actual.c_iflag == expected.c_iflag)
    #expect(actual.c_oflag == expected.c_oflag)
    #expect(actual.c_cflag == expected.c_cflag)
    #expect(actual.c_lflag == expected.c_lflag)
  }
}

final class PseudoTerminal {
  private(set) var master: Int32
  private(set) var slave: Int32
  let slavePath: String
  private var isClosed = false

  init() throws {
    var masterDescriptor: Int32 = -1
    var slaveDescriptor: Int32 = -1
    guard openpty(&masterDescriptor, &slaveDescriptor, nil, nil, nil) == 0 else {
      throw SecureTerminalCredentialError.unavailable
    }
    guard let path = ttyname(slaveDescriptor) else {
      Darwin.close(masterDescriptor)
      Darwin.close(slaveDescriptor)
      throw SecureTerminalCredentialError.unavailable
    }
    master = masterDescriptor
    slave = slaveDescriptor
    slavePath = String(cString: path)
  }

  func state() throws -> termios {
    var value = termios()
    guard tcgetattr(slave, &value) == 0 else {
      throw SecureTerminalCredentialError.unavailable
    }
    return value
  }

  func readUntil(marker: String, timeoutMilliseconds: Int32) throws -> String {
    let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
    var output = [UInt8]()
    var bytes = [UInt8](repeating: 0, count: 256)
    while ContinuousClock.now < deadline {
      var descriptor = pollfd(fd: master, events: Int16(POLLIN), revents: 0)
      let pollResult = Darwin.poll(&descriptor, 1, 20)
      if pollResult < 0, errno != EINTR {
        throw SecureTerminalCredentialError.unavailable
      }
      if pollResult <= 0 { continue }
      let count = bytes.withUnsafeMutableBytes {
        Darwin.read(master, $0.baseAddress, $0.count)
      }
      if count < 0, errno != EINTR && errno != EAGAIN {
        throw SecureTerminalCredentialError.unavailable
      }
      if count > 0 {
        output.append(contentsOf: bytes.prefix(count))
        let decoded = String(decoding: output, as: UTF8.self)
        if decoded.contains(marker) { return decoded }
      }
    }
    throw SecureTerminalCredentialError.unavailable
  }

  func hasReadableData(timeoutMilliseconds: Int32) throws -> Bool {
    var descriptor = pollfd(fd: master, events: Int16(POLLIN), revents: 0)
    let result = Darwin.poll(&descriptor, 1, timeoutMilliseconds)
    if result < 0, errno != EINTR {
      throw SecureTerminalCredentialError.unavailable
    }
    return result > 0 && descriptor.revents & Int16(POLLIN) != 0
  }

  func writeLine(_ value: String) throws {
    let bytes = Array((value + "\n").utf8)
    let written = bytes.withUnsafeBytes {
      Darwin.write(master, $0.baseAddress, $0.count)
    }
    guard written == bytes.count else {
      throw SecureTerminalCredentialError.unavailable
    }
  }

  func close() {
    guard !isClosed else { return }
    isClosed = true
    Darwin.close(master)
    Darwin.close(slave)
  }

  deinit { close() }
}
