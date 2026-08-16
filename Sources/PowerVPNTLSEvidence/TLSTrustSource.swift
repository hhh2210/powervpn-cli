import Foundation
import Network
import PowerVPNPortal
import Security

enum TLSTrustSourceEvent: Equatable, Sendable {
  case captured(TLSTrustSnapshot)
  case timedOut
  case invalidEvidence
  case unavailable
}

protocol TLSTrustSource: AnyObject, Sendable {
  func start(_ handler: @escaping @Sendable (TLSTrustSourceEvent) -> Void)
  func cancel()
  func progressSnapshot() -> TLSPeerProgressSnapshot
}

protocol TLSNetworkConnection: AnyObject, Sendable {
  func setEvidenceStateUpdateHandler(
    _ handler: (@Sendable (NWConnection.State) -> Void)?
  )
  func startEvidenceConnection(on queue: DispatchQueue)
  func cancelEvidenceConnection()
}

extension NWConnection: TLSNetworkConnection {
  func setEvidenceStateUpdateHandler(
    _ handler: (@Sendable (NWConnection.State) -> Void)?
  ) {
    stateUpdateHandler = handler
  }

  func startEvidenceConnection(on queue: DispatchQueue) { start(queue: queue) }
  func cancelEvidenceConnection() { cancel() }
}

final class NetworkTLSTrustSource: TLSTrustSource, @unchecked Sendable {
  typealias ConnectionFactory =
    @Sendable (
      NWEndpoint.Host,
      NWEndpoint.Port,
      NWParameters
    ) -> any TLSNetworkConnection

  static let observationHoldMilliseconds = 250

  private let host: String?
  private let portNumber: UInt16?

  private let queue = DispatchQueue(label: "org.powervpn.tls-peer-evidence")
  private let connectionFactory: ConnectionFactory
  private let chainCapturer: any TLSPeerChainCapturing
  private let trustEvaluator: any TLSAsyncTrustEvaluating
  private let lifecycle = StickyConnectionLifecycle<
    any TLSNetworkConnection, TLSTrustSourceEvent
  >()
  private let verifyGate = TLSVerifyInvocationGate()
  private let progress = TLSPeerProgressRecorder()

  init(
    host: String? = (try? PowerVPNTargetsConfiguration.currentMachine())?.portalOrigin.host,
    port: UInt16? = {
      guard
        let configured = try? PowerVPNTargetsConfiguration.currentMachine(),
        let value = configured.portalOrigin.port
      else { return nil }
      return UInt16(exactly: value)
    }(),
    connectionFactory: @escaping ConnectionFactory = { host, port, parameters in
      NWConnection(host: host, port: port, using: parameters)
    },
    chainCapturer: any TLSPeerChainCapturing = MetadataTLSPeerChainCapturer(),
    trustEvaluator: any TLSAsyncTrustEvaluating = AsyncSecTrustEvaluator()
  ) {
    self.host = host
    portNumber = port
    self.connectionFactory = connectionFactory
    self.chainCapturer = chainCapturer
    self.trustEvaluator = trustEvaluator
  }

  func start(_ handler: @escaping @Sendable (TLSTrustSourceEvent) -> Void) {
    guard lifecycle.begin(handler) else {
      handler(.unavailable)
      return
    }
    guard let host, let portNumber, let port = NWEndpoint.Port(rawValue: portNumber) else {
      deliver(.unavailable)
      return
    }

    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_verify_block(
      tls.securityProtocolOptions,
      { [weak self] metadata, _, completion in
        let rejection = TLSVerifyCompletionOnce(
          completion,
          onInvoke: { [weak self] in self?.progress.recordVerifyInvoked() },
          onReturn: { [weak self] in self?.progress.recordVerifyReturned() }
        )
        guard let self else {
          rejection.reject()
          return
        }
        guard lifecycle.acceptsCallbacks else {
          rejection.reject()
          return
        }
        let isFirstVerify = verifyGate.begin()
        progress.recordVerifyEntry(isDuplicate: !isFirstVerify)
        guard isFirstVerify else {
          rejection.reject()
          deliver(.invalidEvidence)
          return
        }

        let captured = chainCapturer.capture(from: metadata)
        switch captured {
        case .success:
          progress.recordMetadataAccessible()
          progress.recordDERCopyCompleted()
        case .failure(.metadataUnavailable):
          break
        case .failure:
          progress.recordMetadataAccessible()
        }
        queue.asyncAfter(
          deadline: .now() + .milliseconds(Self.observationHoldMilliseconds)
        ) { [weak self] in
          rejection.reject()
          guard let self, lifecycle.acceptsCallbacks else { return }
          handleCapturedChain(captured)
        }
      },
      queue
    )
    let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    let connection = connectionFactory(
      NWEndpoint.Host(host), port, parameters
    )
    connection.setEvidenceStateUpdateHandler { [weak self] state in
      guard let self, lifecycle.acceptsCallbacks else { return }
      switch state {
      case .preparing:
        progress.recordPreparing()
      case .waiting:
        progress.recordWaiting()
      case .failed:
        progress.recordFailed()
        if !verifyGate.hasBegun { deliver(.unavailable) }
      case .ready:
        progress.recordReady()
        deliver(.invalidEvidence)
      default:
        break
      }
    }
    let didStart = lifecycle.publishAndStart(connection) { connection in
      progress.recordConnectionStarted()
      connection.startEvidenceConnection(on: queue)
    }
    guard didStart else {
      connection.setEvidenceStateUpdateHandler(nil)
      connection.cancelEvidenceConnection()
      return
    }
  }

  func cancel() {
    trustEvaluator.cancel()
    guard let connection = lifecycle.cancel() else { return }
    connection.setEvidenceStateUpdateHandler(nil)
    connection.cancelEvidenceConnection()
  }

  func progressSnapshot() -> TLSPeerProgressSnapshot { progress.snapshot() }

  private func handleCapturedChain(
    _ captured: Result<TLSPeerCertificateChain, TLSPeerChainCaptureError>
  ) {
    guard let host else {
      deliver(.unavailable)
      return
    }
    switch captured {
    case .success(let chain):
      trustEvaluator.evaluate(
        chain: chain,
        exactHost: host,
        phase: { [weak self] phase in self?.progress.record(phase) },
        completion: { [weak self] result in
          guard let self else { return }
          queue.async { [weak self] in self?.handleEvaluation(result) }
        }
      )
    case .failure(.metadataUnavailable):
      deliver(.unavailable)
    case .failure:
      deliver(.invalidEvidence)
    }
  }

  private func handleEvaluation(
    _ result: Result<TLSTrustSnapshot, TLSAsyncTrustEvaluationError>
  ) {
    guard lifecycle.acceptsCallbacks else { return }
    switch result {
    case .success(let snapshot):
      deliver(.captured(snapshot))
    case .failure(.timedOut):
      deliver(.timedOut)
    case .failure(.invalidChain), .failure(.duplicateCallback), .failure(.invalidState):
      deliver(.invalidEvidence)
    case .failure(.trustSetup), .failure(.evaluationStart):
      deliver(.unavailable)
    }
  }

  private func deliver(_ event: TLSTrustSourceEvent) {
    lifecycle.takeHandler()?(event)
  }

  deinit { cancel() }
}

final class TLSVerifyCompletionOnce: @unchecked Sendable {
  private let lock = NSLock()
  private var callback: sec_protocol_verify_complete_t?
  private var onInvoke: (@Sendable () -> Void)?
  private var onReturn: (@Sendable () -> Void)?

  init(
    _ callback: @escaping sec_protocol_verify_complete_t,
    onInvoke: @escaping @Sendable () -> Void = {},
    onReturn: @escaping @Sendable () -> Void = {}
  ) {
    self.callback = callback
    self.onInvoke = onInvoke
    self.onReturn = onReturn
  }

  func reject() {
    let retained = lock.withLock {
      () -> (
        sec_protocol_verify_complete_t, @Sendable () -> Void, @Sendable () -> Void
      )? in
      guard let callback, let onInvoke, let onReturn else { return nil }
      self.callback = nil
      self.onInvoke = nil
      self.onReturn = nil
      return (callback, onInvoke, onReturn)
    }
    guard let retained else { return }
    retained.1()
    retained.0(false)
    retained.2()
  }
}

final class TLSVerifyInvocationGate: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0

  func begin() -> Bool {
    lock.withLock {
      count += 1
      return count == 1
    }
  }

  var hasBegun: Bool { lock.withLock { count > 0 } }
}
