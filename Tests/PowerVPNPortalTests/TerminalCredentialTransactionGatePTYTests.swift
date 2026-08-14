import Darwin
import Foundation
import Testing

@testable import PowerVPNPortal

@Suite(.serialized) struct TerminalCredentialTransactionGatePTYTests {
  @Test func wholeCredentialTransactionsCannotOverlapOnTheSameTerminal() async throws {
    let terminal = try PseudoTerminal()
    defer { terminal.close() }
    let originalState = try terminal.state()
    let ledger = TerminalTransactionLedger()
    let gate = TerminalCredentialTransactionGate(
      waitObserver: { ledger.recordGateWait() }
    )
    let firstReader = DarwinSecureTerminalCredentialReader(
      driver: ObservedTerminalCredentialDriver(
        readerID: 1,
        terminalPath: terminal.slavePath,
        ledger: ledger
      ),
      transactionGate: gate
    )
    let secondReader = DarwinSecureTerminalCredentialReader(
      driver: ObservedTerminalCredentialDriver(
        readerID: 2,
        terminalPath: terminal.slavePath,
        ledger: ledger
      ),
      transactionGate: gate
    )

    let firstTask = Task.detached { await credentialError(from: firstReader) }
    defer { firstTask.cancel() }
    _ = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.username.rawValue,
      timeoutMilliseconds: 1_000
    )

    let secondTask = Task.detached { try secondReader.readCredentials() }
    defer { secondTask.cancel() }
    #expect(await waitForGateWait { ledger.gateWaitObserved })
    #expect(try !terminal.hasReadableData(timeoutMilliseconds: 10))
    #expect(ledger.observations == [TerminalReadObservation(readerID: 1, prompt: .username)])

    firstTask.cancel()
    #expect(await firstTask.value == .cancelled)
    _ = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.username.rawValue,
      timeoutMilliseconds: 1_000
    )
    #expect(try terminal.state().c_lflag & tcflag_t(ECHO | ECHONL) == 0)
    try await Task.sleep(for: .milliseconds(75))
    #expect(try terminal.state().c_lflag & tcflag_t(ECHO | ECHONL) == 0)

    try terminal.writeLine("second-user")
    _ = try terminal.readUntil(
      marker: SecureTerminalCredentialPrompt.password.rawValue,
      timeoutMilliseconds: 1_000
    )
    try terminal.writeLine("second-password")
    let credentials = try await secondTask.value
    credentials.erase()

    #expect(
      ledger.observations == [
        TerminalReadObservation(readerID: 1, prompt: .username),
        TerminalReadObservation(readerID: 2, prompt: .username),
        TerminalReadObservation(readerID: 2, prompt: .password),
      ]
    )
    #expect(ledger.maximumConcurrentReads == 1)
    let finalState = try terminal.state()
    #expect(finalState.c_iflag == originalState.c_iflag)
    #expect(finalState.c_oflag == originalState.c_oflag)
    #expect(finalState.c_cflag == originalState.c_cflag)
    #expect(finalState.c_lflag == originalState.c_lflag)
  }
}

private struct ObservedTerminalCredentialDriver: TerminalCredentialDriving {
  let readerID: Int
  let terminalPath: String
  let ledger: TerminalTransactionLedger

  func read(
    prompt: SecureTerminalCredentialPrompt,
    into buffer: UnsafeMutablePointer<CChar>,
    capacity: Int,
    disableEcho: Bool
  ) -> TerminalCredentialDriverResult {
    ledger.beginRead(readerID: readerID, prompt: prompt)
    defer { ledger.endRead() }
    return DarwinTerminalCredentialDriver(terminalPath: terminalPath).read(
      prompt: prompt,
      into: buffer,
      capacity: capacity,
      disableEcho: disableEcho
    )
  }
}

private struct TerminalReadObservation: Equatable {
  let readerID: Int
  let prompt: SecureTerminalCredentialPrompt
}

private final class TerminalTransactionLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var activeReads = 0
  private var maximumReads = 0
  private var reads: [TerminalReadObservation] = []
  private var observedGateWait = false

  var observations: [TerminalReadObservation] { lock.withLock { reads } }
  var maximumConcurrentReads: Int { lock.withLock { maximumReads } }
  var gateWaitObserved: Bool { lock.withLock { observedGateWait } }

  func recordGateWait() {
    lock.withLock { observedGateWait = true }
  }

  func beginRead(readerID: Int, prompt: SecureTerminalCredentialPrompt) {
    lock.withLock {
      activeReads += 1
      maximumReads = max(maximumReads, activeReads)
      reads.append(TerminalReadObservation(readerID: readerID, prompt: prompt))
    }
  }

  func endRead() {
    lock.withLock { activeReads -= 1 }
  }
}

private func credentialError(
  from reader: DarwinSecureTerminalCredentialReader
) async -> SecureTerminalCredentialError? {
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

private func waitForGateWait(
  _ condition: @escaping @Sendable () -> Bool
) async -> Bool {
  let deadline = ContinuousClock.now.advanced(by: .seconds(1))
  while ContinuousClock.now < deadline {
    if condition() { return true }
    try? await Task.sleep(for: .milliseconds(1))
  }
  return condition()
}
