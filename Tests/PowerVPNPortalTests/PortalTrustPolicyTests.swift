import Foundation
import Testing

@testable import PowerVPNPortal

@Suite struct PortalTrustPolicyTests {
  private let policy = PortalTrustPolicy(exactHost: "192.0.2.1")

  @Test func exactHostRequiresSuccessfulSystemTrust() {
    #expect(
      decision(host: "192.0.2.1", systemTrustAccepted: true) == .useSystemCredential)
    #expect(decision(host: "192.0.2.1", systemTrustAccepted: false) == .reject)
  }

  @Test func hostComparisonIsExactAndFailsBeforeTrustEvaluation() {
    let ledger = EvaluationLedger()
    let disposition = policy.authenticationDisposition(
      authenticationMethod: NSURLAuthenticationMethodServerTrust,
      host: "166.111.143.019",
      serverTrustAvailable: true,
      evaluateSystemTrust: {
        ledger.record()
        return true
      }
    )

    #expect(disposition == .reject)
    #expect(ledger.count == 0)
  }

  @Test func missingTrustAndOtherAuthenticationMethodsFailClosed() {
    #expect(
      policy.authenticationDisposition(
        authenticationMethod: NSURLAuthenticationMethodServerTrust,
        host: "192.0.2.1",
        serverTrustAvailable: false,
        evaluateSystemTrust: { true }
      ) == .reject)
    #expect(
      policy.authenticationDisposition(
        authenticationMethod: NSURLAuthenticationMethodHTTPBasic,
        host: "192.0.2.1",
        serverTrustAvailable: true,
        evaluateSystemTrust: { true }
      ) == .reject)
  }

  @Test func sameOriginAndCrossOriginRedirectsAreBothRejected() throws {
    let source = try #require(URL(string: "https://192.0.2.1:4443/login"))
    let sameOrigin = try #require(URL(string: "https://192.0.2.1:4443/next"))
    let crossOrigin = try #require(URL(string: "https://example.invalid/next"))

    #expect(policy.redirectDisposition(from: source, to: sameOrigin) == .reject)
    #expect(policy.redirectDisposition(from: source, to: crossOrigin) == .reject)
  }

  @Test func urlSessionDelegateCancelsBothRedirectCallbacksBeforeSecondRequest() throws {
    let source = try #require(URL(string: "https://192.0.2.1:4443/login"))
    let targets = [
      try #require(URL(string: "https://192.0.2.1:4443/next")),
      try #require(URL(string: "https://example.invalid/next")),
    ]
    let delegate = PortalURLSessionDelegate(
      policy: policy,
      evaluateSystemTrust: { _, _ in false }
    )
    let session = URLSession(configuration: .ephemeral)
    defer { session.invalidateAndCancel() }

    for target in targets {
      let task = session.dataTask(with: source)
      let response = try #require(
        HTTPURLResponse(
          url: source,
          statusCode: 302,
          httpVersion: "HTTP/1.1",
          headerFields: ["Location": target.absoluteString]
        ))
      let ledger = RedirectCallbackLedger()
      delegate.urlSession(
        session,
        task: task,
        willPerformHTTPRedirection: response,
        newRequest: URLRequest(url: target),
        completionHandler: { ledger.record($0) }
      )
      #expect(ledger.callCount == 1)
      #expect(ledger.receivedRequest == false)
    }
  }

  @Test func urlSessionDelegateRejectsEveryTaskLevelAuthenticationChallenge() throws {
    let source = try #require(URL(string: "https://192.0.2.1:4443/login"))
    let delegate = PortalURLSessionDelegate(
      policy: policy,
      evaluateSystemTrust: { _, _ in true }
    )
    let session = URLSession(configuration: .ephemeral)
    defer { session.invalidateAndCancel() }
    let task = session.dataTask(with: source)
    let protectionSpace = URLProtectionSpace(
      host: "192.0.2.1",
      port: 4_443,
      protocol: "https",
      realm: "synthetic",
      authenticationMethod: NSURLAuthenticationMethodHTTPBasic
    )
    let challenge = URLAuthenticationChallenge(
      protectionSpace: protectionSpace,
      proposedCredential: nil,
      previousFailureCount: 0,
      failureResponse: nil,
      error: nil,
      sender: ChallengeSender()
    )
    let ledger = ChallengeCallbackLedger()

    delegate.urlSession(
      session,
      task: task,
      didReceive: challenge,
      completionHandler: { ledger.record(disposition: $0, credential: $1) }
    )
    #expect(ledger.callCount == 1)
    #expect(ledger.disposition == .cancelAuthenticationChallenge)
    #expect(!ledger.credentialPresent)
  }

  private func decision(
    host: String,
    systemTrustAccepted: Bool
  ) -> PortalAuthenticationDisposition {
    policy.authenticationDisposition(
      authenticationMethod: NSURLAuthenticationMethodServerTrust,
      host: host,
      serverTrustAvailable: true,
      evaluateSystemTrust: { systemTrustAccepted }
    )
  }
}

private final class EvaluationLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var storage = 0

  var count: Int { lock.withLock { storage } }

  func record() {
    lock.withLock { storage += 1 }
  }
}

private final class RedirectCallbackLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0
  private var received = false

  var callCount: Int { lock.withLock { calls } }
  var receivedRequest: Bool { lock.withLock { received } }

  func record(_ request: URLRequest?) {
    lock.withLock {
      calls += 1
      received = request != nil
    }
  }
}

private final class ChallengeCallbackLedger: @unchecked Sendable {
  private let lock = NSLock()
  private var calls = 0
  private var recordedDisposition: URLSession.AuthChallengeDisposition?
  private var receivedCredential = false

  var callCount: Int { lock.withLock { calls } }
  var disposition: URLSession.AuthChallengeDisposition? {
    lock.withLock { recordedDisposition }
  }
  var credentialPresent: Bool { lock.withLock { receivedCredential } }

  func record(
    disposition: URLSession.AuthChallengeDisposition,
    credential: URLCredential?
  ) {
    lock.withLock {
      calls += 1
      recordedDisposition = disposition
      receivedCredential = credential != nil
    }
  }
}

private final class ChallengeSender: NSObject, URLAuthenticationChallengeSender {
  func use(_: URLCredential, for _: URLAuthenticationChallenge) {}
  func continueWithoutCredential(for _: URLAuthenticationChallenge) {}
  func cancel(_: URLAuthenticationChallenge) {}
  func performDefaultHandling(for _: URLAuthenticationChallenge) {}
  func rejectProtectionSpaceAndContinue(with _: URLAuthenticationChallenge) {}
}
