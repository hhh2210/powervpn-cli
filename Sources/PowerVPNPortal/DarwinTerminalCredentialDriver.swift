import Darwin

enum TerminalCredentialDriverResult: Sendable {
  case success(Int)
  case cancelled
  case failure(Int32)
}

protocol TerminalCredentialDriving: Sendable {
  func read(
    prompt: SecureTerminalCredentialPrompt,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int,
    disableEcho: Bool
  ) -> TerminalCredentialDriverResult
}

struct DarwinTerminalCredentialDriver: TerminalCredentialDriving {
  static let cancellationCheckMilliseconds: Int = 50

  private let terminalPath: String

  init(terminalPath: String = "/dev/tty") {
    self.terminalPath = terminalPath
  }

  func read(
    prompt: SecureTerminalCredentialPrompt,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int,
    disableEcho: Bool
  ) -> TerminalCredentialDriverResult {
    guard capacity > 1 else { return .failure(EINVAL) }
    if Task.isCancelled { return .cancelled }

    let descriptor = terminalPath.withCString {
      Darwin.open($0, O_RDWR | O_CLOEXEC | O_NONBLOCK)
    }
    guard descriptor >= 0 else { return .failure(errno) }
    defer { Darwin.close(descriptor) }

    var originalState = termios()
    guard tcgetattr(descriptor, &originalState) == 0 else { return .failure(errno) }
    var restored = false
    defer {
      if !restored {
        var state = originalState
        _ = tcsetattr(descriptor, TCSANOW, &state)
      }
    }

    if disableEcho {
      var hiddenState = originalState
      hiddenState.c_lflag &= ~tcflag_t(ECHO | ECHONL)
      guard tcsetattr(descriptor, TCSANOW, &hiddenState) == 0 else {
        return .failure(errno)
      }
    }

    let result: TerminalCredentialDriverResult
    switch write(prompt.rawValue, to: descriptor) {
    case .success:
      result = readLine(from: descriptor, into: buffer, capacity: capacity)
    case .cancelled:
      result = .cancelled
    case .failure(let errorNumber):
      result = .failure(errorNumber)
    }

    if disableEcho {
      _ = "\n".withCString { Darwin.write(descriptor, $0, 1) }
    }
    var state = originalState
    guard tcsetattr(descriptor, TCSANOW, &state) == 0 else {
      return .failure(errno)
    }
    restored = true
    return result
  }

  private func write(_ value: String, to descriptor: Int32) -> TerminalCredentialDriverResult {
    value.withCString { bytes in
      var offset = 0
      let count = strlen(bytes)
      while offset < count {
        if Task.isCancelled { return .cancelled }
        let written = Darwin.write(descriptor, bytes + offset, count - offset)
        if written > 0 {
          offset += written
          continue
        }
        if written < 0, errno != EAGAIN, errno != EWOULDBLOCK, errno != EINTR {
          return .failure(errno)
        }
        switch waitBeforeRetrying(descriptor: descriptor, events: Int16(POLLOUT)) {
        case .ready:
          continue
        case .cancelled:
          return .cancelled
        case .failure(let errorNumber):
          return .failure(errorNumber)
        }
      }
      return .success(count)
    }
  }

  private func readLine(
    from descriptor: Int32,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int
  ) -> TerminalCredentialDriverResult {
    var count = 0
    while count < capacity - 1 {
      if Task.isCancelled { return .cancelled }
      let bytesRead = Darwin.read(descriptor, buffer + count, capacity - 1 - count)
      if bytesRead == 0 {
        buffer[count] = 0
        return .success(count)
      }
      if bytesRead < 0 {
        if errno != EAGAIN, errno != EWOULDBLOCK, errno != EINTR {
          return .failure(errno)
        }
        switch waitBeforeRetrying(descriptor: descriptor, events: Int16(POLLIN)) {
        case .ready:
          continue
        case .cancelled:
          return .cancelled
        case .failure(let errorNumber):
          return .failure(errorNumber)
        }
      }
      let end = count + bytesRead
      while count < end {
        if buffer[count] == 10 {
          var lineCount = count
          if lineCount > 0, buffer[lineCount - 1] == 13 {
            lineCount -= 1
          }
          buffer[lineCount] = 0
          return .success(lineCount)
        }
        count += 1
      }
    }
    buffer[count] = 0
    return .success(count)
  }

  private func waitBeforeRetrying(
    descriptor: Int32,
    events: Int16
  ) -> RetryWaitResult {
    var descriptorState = pollfd(fd: descriptor, events: events, revents: 0)
    while true {
      if Task.isCancelled { return .cancelled }
      let result = Darwin.poll(
        &descriptorState,
        1,
        Int32(Self.cancellationCheckMilliseconds)
      )
      if result >= 0 {
        return Task.isCancelled ? .cancelled : .ready
      }
      let errorNumber = errno
      guard errorNumber == EINTR else { return .failure(errorNumber) }
    }
  }

  private enum RetryWaitResult {
    case ready
    case cancelled
    case failure(Int32)
  }
}
