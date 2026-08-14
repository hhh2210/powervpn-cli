import Foundation
import Security

typealias PortalSystemTrustEvaluator = (SecTrust, String) -> Bool

/// Internal URLSession test seam. Production Portal traffic is exclusively
/// connection-bound through the fixed pinned libcurl transport.
public final class PortalURLSessionDelegate:
  NSObject,
  URLSessionDelegate,
  URLSessionTaskDelegate,
  @unchecked Sendable
{
  private let policy: PortalTrustPolicy
  private let evaluateSystemTrust: PortalSystemTrustEvaluator

  init(
    policy: PortalTrustPolicy,
    evaluateSystemTrust: @escaping PortalSystemTrustEvaluator
  ) {
    self.policy = policy
    self.evaluateSystemTrust = evaluateSystemTrust
  }

  public func urlSession(
    _: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler:
      @escaping @Sendable (
        URLSession.AuthChallengeDisposition, URLCredential?
      ) -> Void
  ) {
    let space = challenge.protectionSpace
    let trust = space.serverTrust
    let disposition = policy.authenticationDisposition(
      authenticationMethod: space.authenticationMethod,
      host: space.host,
      serverTrustAvailable: trust != nil,
      evaluateSystemTrust: { [evaluateSystemTrust] in
        guard let trust else { return false }
        return evaluateSystemTrust(trust, space.host)
      }
    )
    guard disposition == .useSystemCredential, let trust else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }

  public func urlSession(
    _: URLSession,
    task _: URLSessionTask,
    didReceive _: URLAuthenticationChallenge,
    completionHandler:
      @escaping @Sendable (
        URLSession.AuthChallengeDisposition, URLCredential?
      ) -> Void
  ) {
    completionHandler(.cancelAuthenticationChallenge, nil)
  }

  public func urlSession(
    _: URLSession,
    task _: URLSessionTask,
    willPerformHTTPRedirection _: HTTPURLResponse,
    newRequest _: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}
