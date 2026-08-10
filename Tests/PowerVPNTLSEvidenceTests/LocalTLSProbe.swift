import Foundation
import Network
import Security

@testable import PowerVPNTLSEvidence

enum LocalTLSServerNameMode: CaseIterable, Sendable {
  case automatic
  case explicitIPAddress
}

struct LocalTLSProbeObservation: Equatable, Sendable {
  let serverNameExtensionCount: Int
  let verifyCallbackCount: Int
  let rejectionCompletionCount: Int
  let metadataChainLength: Int
  let metadataLeafSHA256: String?
  let clientReady: Bool
  let applicationDataSent: Bool
}

enum LocalTLSProbeError: Error {
  case listenerFailed
  case listenerStartTimedOut
  case clientHelloTimedOut
  case verificationTimedOut
  case malformedClientHello
}

enum LocalTLSProbe {
  private static let loopback = NWEndpoint.Host("127.0.0.1")
  private static let timeout: DispatchTimeInterval = .seconds(3)
  private static let postRejectionWindow: DispatchTimeInterval = .milliseconds(100)
  private static let maximumClientHelloBytes = 18_432

  static func run(
    mode: LocalTLSServerNameMode,
    identity: sec_identity_t
  ) throws -> LocalTLSProbeObservation {
    let serverNameExtensionCount = try captureClientHello(mode: mode)
    let verification = try observeVerification(mode: mode, identity: identity)
    return LocalTLSProbeObservation(
      serverNameExtensionCount: serverNameExtensionCount,
      verifyCallbackCount: verification.callbackCount,
      rejectionCompletionCount: verification.completionCount,
      metadataChainLength: verification.chainLength,
      metadataLeafSHA256: verification.leafSHA256,
      clientReady: verification.ready,
      applicationDataSent: false
    )
  }

  private static func captureClientHello(mode: LocalTLSServerNameMode) throws -> Int {
    let capture = LocalTLSLatch<Result<Int, LocalTLSProbeError>>()
    let listener = try startListener(parameters: loopbackParameters()) { connection in
      connection.start(queue: queue)
      receiveClientHello(Data(), from: connection, capture: capture)
    }
    let client = makeClient(port: listener.port, mode: mode, verification: nil)
    client.start(queue: queue)
    defer {
      client.cancel()
      listener.listener.cancel()
    }
    guard let result = capture.wait(timeout: timeout) else {
      throw LocalTLSProbeError.clientHelloTimedOut
    }
    return try result.get()
  }

  private static func observeVerification(
    mode: LocalTLSServerNameMode,
    identity: sec_identity_t
  ) throws -> (
    callbackCount: Int,
    completionCount: Int,
    chainLength: Int,
    leafSHA256: String?,
    ready: Bool
  ) {
    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
    let serverConnection = LocalTLSLocked<NWConnection?>(nil)
    let listener = try startListener(parameters: loopbackParameters(tls: tls)) { connection in
      serverConnection.set(connection)
      connection.start(queue: queue)
    }
    let recorder = LocalTLSVerificationRecorder()
    let callbackObserved = LocalTLSLatch<Bool>()
    let client = makeClient(port: listener.port, mode: mode) { metadata, completion in
      recorder.recordCallback()
      if case .success(let chain) = MetadataTLSPeerChainCapturer().capture(from: metadata) {
        recorder.recordChain(chain)
      }
      completion(false)
      recorder.recordRejectionCompletion()
      callbackObserved.resolve(true)
    }
    client.stateUpdateHandler = { state in
      switch state {
      case .ready:
        recorder.recordReady()
      default:
        break
      }
    }
    client.start(queue: queue)
    defer {
      client.stateUpdateHandler = nil
      client.cancel()
      serverConnection.value()?.cancel()
      listener.listener.cancel()
    }
    guard callbackObserved.wait(timeout: timeout) == true else {
      throw LocalTLSProbeError.verificationTimedOut
    }
    _ = DispatchSemaphore(value: 0).wait(timeout: .now() + postRejectionWindow)
    let result = recorder.snapshot()
    return (
      callbackCount: result.callbackCount,
      completionCount: result.completionCount,
      chainLength: result.chainLength,
      leafSHA256: result.leafSHA256,
      ready: result.ready
    )
  }

  private static let queue = DispatchQueue(label: "org.powervpn.tests.local-tls")

  private static func makeClient(
    port: NWEndpoint.Port,
    mode: LocalTLSServerNameMode,
    verification: ((sec_protocol_metadata_t, @escaping sec_protocol_verify_complete_t) -> Void)?
  ) -> NWConnection {
    let tls = NWProtocolTLS.Options()
    if mode == .explicitIPAddress {
      "127.0.0.1".withCString {
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, $0)
      }
    }
    if let verification {
      sec_protocol_options_set_verify_block(
        tls.securityProtocolOptions,
        { metadata, _, completion in verification(metadata, completion) },
        queue
      )
    }
    return NWConnection(
      host: loopback,
      port: port,
      using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    )
  }

  private static func loopbackParameters(tls: NWProtocolTLS.Options? = nil) -> NWParameters {
    let parameters: NWParameters
    if let tls {
      parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    } else {
      parameters = .tcp
    }
    parameters.requiredLocalEndpoint = .hostPort(host: loopback, port: .any)
    return parameters
  }

  private static func startListener(
    parameters: NWParameters,
    newConnection: @escaping @Sendable (NWConnection) -> Void
  ) throws -> (listener: NWListener, port: NWEndpoint.Port) {
    let listener = try NWListener(using: parameters)
    let started = LocalTLSLatch<Result<NWEndpoint.Port, LocalTLSProbeError>>()
    listener.newConnectionHandler = newConnection
    listener.stateUpdateHandler = { state in
      switch state {
      case .ready:
        if let port = listener.port {
          started.resolve(.success(port))
        } else {
          started.resolve(.failure(.listenerFailed))
        }
      case .failed:
        started.resolve(.failure(.listenerFailed))
      default:
        break
      }
    }
    listener.start(queue: queue)
    guard let result = started.wait(timeout: timeout) else {
      listener.cancel()
      throw LocalTLSProbeError.listenerStartTimedOut
    }
    do {
      return (listener, try result.get())
    } catch {
      listener.cancel()
      throw error
    }
  }

  private static func receiveClientHello(
    _ accumulated: Data,
    from connection: NWConnection,
    capture: LocalTLSLatch<Result<Int, LocalTLSProbeError>>
  ) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: maximumClientHelloBytes) {
      bytes, _, complete, error in
      var combined = accumulated
      if let bytes { combined.append(bytes) }
      if let recordLength = TLSClientHelloParser.completeRecordLength(combined) {
        guard recordLength > 0, recordLength <= maximumClientHelloBytes else {
          capture.resolve(.failure(.malformedClientHello))
          connection.cancel()
          return
        }
        if combined.count < recordLength {
          guard !complete, error == nil else {
            capture.resolve(.failure(.malformedClientHello))
            connection.cancel()
            return
          }
          receiveClientHello(combined, from: connection, capture: capture)
          return
        }
        guard let count = TLSClientHelloParser.serverNameExtensionCount(combined) else {
          capture.resolve(.failure(.malformedClientHello))
          connection.cancel()
          return
        }
        capture.resolve(.success(count))
        connection.cancel()
      } else if complete || error != nil || combined.count >= maximumClientHelloBytes {
        capture.resolve(.failure(.malformedClientHello))
        connection.cancel()
      } else {
        receiveClientHello(combined, from: connection, capture: capture)
      }
    }
  }
}
