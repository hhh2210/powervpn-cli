import Darwin
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct SecureTerminalCredentialsTests {
  @Test func readsExactlyTwoClosedNoEchoPromptsAndCascadesErase() throws {
    let ledger = ErasureLedger()
    let driver = ScriptedReadPassphraseDriver([
      .value(.username, Array("user-sentinel".utf8)),
      .value(.password, Array("password-sentinel".utf8)),
    ])
    let reader = testReader(driver: driver, ledger: ledger)
    let credentials = try reader.readCredentials()

    #expect(driver.calls.map(\.prompt) == [.username, .password])
    #expect(driver.calls.allSatisfy { $0.flags == RPP_ECHO_OFF | RPP_REQUIRE_TTY })
    #expect(credentials.usernameByteCount == 13)
    #expect(credentials.passwordByteCount == 17)
    #expect(
      try credentials.withUsernameBytes { String(decoding: $0, as: UTF8.self) } == "user-sentinel")
    #expect(
      try credentials.withPasswordBytes { String(decoding: $0, as: UTF8.self) }
        == "password-sentinel")

    credentials.erase()
    #expect(credentials.usernameByteCount == 0)
    #expect(credentials.passwordByteCount == 0)
    #expect(ledger.secureErased == [.username, .password])
    #expect(ledger.onlyZeroes)
    #expect(ledger.bufferErased == [.username, .password])
  }

  @Test func deinitCascadesToBothOwnedSecureBuffers() throws {
    let ledger = ErasureLedger()
    do {
      let username = try SecureBytes(copying: Array("user".utf8)) {
        ledger.recordSecure(.username, bytes: $0)
      }
      let password = try SecureBytes(copying: Array("pass".utf8)) {
        ledger.recordSecure(.password, bytes: $0)
      }
      _ = PortalCredentials(username: username, password: password)
    }
    #expect(ledger.secureErased == [.username, .password])
    #expect(ledger.onlyZeroes)
  }

  @Test func passwordCancellationErasesPartialUsernameAndBothCBuffers() throws {
    let sentinel = "partial-username-sentinel"
    let ledger = ErasureLedger()
    let driver = ScriptedReadPassphraseDriver([
      .value(.username, Array(sentinel.utf8)),
      .failure(.password, EINTR),
    ])

    #expect(throws: SecureTerminalCredentialError.cancelled) {
      _ = try testReader(driver: driver, ledger: ledger).readCredentials()
    }
    #expect(ledger.secureErased == [.username])
    #expect(ledger.bufferErased == [.username, .password])
    #expect(ledger.onlyZeroes)
    #expect(!String(reflecting: SecureTerminalCredentialError.cancelled).contains(sentinel))
  }

  @Test(arguments: [SecureTerminalCredentialPrompt.username, .password])
  func emptyInputFailsClosedWithoutEcho(_ emptyPrompt: SecureTerminalCredentialPrompt) throws {
    let ledger = ErasureLedger()
    let steps: [ReadStep] =
      emptyPrompt == .username
      ? [.value(.username, [])]
      : [.value(.username, Array("user".utf8)), .value(.password, [])]
    let driver = ScriptedReadPassphraseDriver(steps)

    do {
      _ = try testReader(driver: driver, ledger: ledger).readCredentials()
      Issue.record("expected empty input rejection")
    } catch let error as SecureTerminalCredentialError {
      #expect(error == .empty(emptyPrompt))
      #expect(!String(reflecting: error).contains("empty-input-secret-sentinel"))
    }
    #expect(
      ledger.bufferErased == (emptyPrompt == .username ? [.username] : [.username, .password]))
    #expect(ledger.secureErased == (emptyPrompt == .username ? [] : [.username]))
    #expect(ledger.onlyZeroes)
  }

  @Test(arguments: [SecureTerminalCredentialPrompt.username, .password])
  func truncationBoundaryIsClassifiedAsTooLong(
    _ longPrompt: SecureTerminalCredentialPrompt
  ) throws {
    let ledger = ErasureLedger()
    let oversized = [UInt8](
      repeating: 0x58,
      count: DarwinSecureTerminalCredentialReader.bufferCapacity - 1
    )
    let steps: [ReadStep] =
      longPrompt == .username
      ? [.value(.username, oversized)]
      : [.value(.username, Array("user".utf8)), .value(.password, oversized)]
    let driver = ScriptedReadPassphraseDriver(steps)

    #expect(throws: SecureTerminalCredentialError.inputTooLong(longPrompt)) {
      _ = try testReader(driver: driver, ledger: ledger).readCredentials()
    }
    #expect(ledger.onlyZeroes)
    #expect(ledger.bufferErased.last == longPrompt)
    #expect(ledger.secureErased == (longPrompt == .username ? [] : [.username]))
  }

  @Test func nonInterruptDriverFailureIsNormalizedAndValueFree() {
    let sentinel = "foreign-driver-error-sentinel"
    let ledger = ErasureLedger()
    let driver = ScriptedReadPassphraseDriver([.failure(.username, EIO)])
    do {
      _ = try testReader(driver: driver, ledger: ledger).readCredentials()
      Issue.record("expected unavailable terminal")
    } catch let error as SecureTerminalCredentialError {
      #expect(error == .unavailable)
      #expect(!String(reflecting: error).contains(sentinel))
    } catch {
      Issue.record("unexpected error category")
    }
    #expect(ledger.bufferErased == [.username])
    #expect(ledger.onlyZeroes)
  }
}

private func testReader(
  driver: ScriptedReadPassphraseDriver,
  ledger: ErasureLedger
) -> DarwinSecureTerminalCredentialReader {
  DarwinSecureTerminalCredentialReader(
    driver: driver,
    bufferEraseObserver: { ledger.recordBuffer($0, bytes: $1) },
    secureEraseObserver: { ledger.recordSecure($0, bytes: $1) }
  )
}

private enum ReadStep: Sendable {
  case value(SecureTerminalCredentialPrompt, [UInt8])
  case failure(SecureTerminalCredentialPrompt, Int32)

  var prompt: SecureTerminalCredentialPrompt {
    switch self {
    case .value(let prompt, _), .failure(let prompt, _): prompt
    }
  }
}

private final class ScriptedReadPassphraseDriver: @unchecked Sendable, ReadPassphraseDriving {
  struct Call: Sendable {
    let prompt: SecureTerminalCredentialPrompt
    let flags: Int32
  }

  private let lock = NSLock()
  private var steps: [ReadStep]
  private var recordedCalls: [Call] = []

  init(_ steps: [ReadStep]) {
    self.steps = steps
  }

  var calls: [Call] {
    lock.withLock { recordedCalls }
  }

  func read(
    prompt: SecureTerminalCredentialPrompt,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int,
    flags: Int32
  ) -> ReadPassphraseDriverResult {
    lock.withLock {
      recordedCalls.append(Call(prompt: prompt, flags: flags))
      guard !steps.isEmpty else { return .failure(EIO) }
      let step = steps.removeFirst()
      guard step.prompt == prompt else { return .failure(EINVAL) }
      switch step {
      case .failure(_, let errorNumber):
        return .failure(errorNumber)
      case .value(_, let bytes):
        let copied = min(bytes.count, capacity - 1)
        for index in 0..<copied {
          buffer[index] = CChar(bitPattern: bytes[index])
        }
        return .success
      }
    }
  }
}

private final class ErasureLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var secure: Set<SecureTerminalCredentialPrompt> = []
  private var buffers: [SecureTerminalCredentialPrompt] = []
  private var zeroesOnly = true

  var secureErased: Set<SecureTerminalCredentialPrompt> {
    lock.withLock { secure }
  }

  var bufferErased: [SecureTerminalCredentialPrompt] {
    lock.withLock { buffers }
  }

  var onlyZeroes: Bool {
    lock.withLock { zeroesOnly }
  }

  func recordSecure(_ prompt: SecureTerminalCredentialPrompt, bytes: UnsafeRawBufferPointer) {
    lock.withLock {
      secure.insert(prompt)
      zeroesOnly = zeroesOnly && bytes.allSatisfy { $0 == 0 }
    }
  }

  func recordBuffer(_ prompt: SecureTerminalCredentialPrompt, bytes: UnsafeRawBufferPointer) {
    lock.withLock {
      buffers.append(prompt)
      zeroesOnly = zeroesOnly && bytes.allSatisfy { $0 == 0 }
    }
  }
}
